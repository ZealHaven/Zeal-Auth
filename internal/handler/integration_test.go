package handler

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"

	"github.com/alicebob/miniredis/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"

	"github.com/zeal/auth/internal/repository"
	"github.com/zeal/auth/internal/service"
)

var (
	integPool   *pgxpool.Pool
	integRDB    *redis.Client
	integMR     *miniredis.Miniredis
	integRouter http.Handler
)

const testEncKey = "0000000000000000000000000000000000000000000000000000000000000001"

func buildIntegRouter() http.Handler {
	keySvc := service.NewKeyService(integPool, testEncKey)

	fositeCfg := DefaultFositeConfig("https://auth.test.com", "test.com")
	fositeCfg.GlobalSecret = []byte("integration-test-secret-32-bytes-long!!!")
	fositeCfg.AdminToken = "test-admin-token"
	fositeCfg.EnforcePKCE = true

	oauthHandler, err := NewFositeServer(integPool, keySvc, fositeCfg)
	if err != nil {
		log.Fatalf("fosite server: %v", err)
	}

	sessionSvc := service.NewSessionService(integRDB)

	oauth2Handler := NewOAuth2Handler(oauthHandler, integPool, keySvc, fositeCfg, sessionSvc)

	userRepo := repository.NewUserRepository(integPool)
	verificationRepo := repository.NewVerificationRepository(integPool)
	resetRepo := repository.NewResetRepository(integPool)
	federatedRepo := repository.NewFederatedRepository(integPool)
	authSvc := service.NewAuthService(userRepo)
	emailSvc := service.NewEmailService(userRepo, verificationRepo, resetRepo, integPool, sessionSvc, nil, "https://auth.test.com")

	brokerSvc := service.NewBrokerService(service.BrokerDeps{
		Users:     userRepo,
		Federated: federatedRepo,
		RDB:       integRDB,
		Google: &oauth2.Config{
			ClientID:     "test-google-id",
			ClientSecret: "test-google-secret",
			Endpoint:     oauth2.Endpoint{AuthURL: "https://accounts.google.com/o/oauth2/auth", TokenURL: "http://localhost:1/token"},
			RedirectURL:  "http://localhost:1/oauth/google/callback",
			Scopes:       []string{"openid", "email", "profile"},
		},
		GitHub: &oauth2.Config{
			ClientID:     "test-github-id",
			ClientSecret: "test-github-secret",
			Endpoint:     oauth2.Endpoint{AuthURL: "https://github.com/login/oauth/authorize", TokenURL: "http://localhost:1/token"},
			RedirectURL:  "http://localhost:1/oauth/github/callback",
			Scopes:       []string{"user:email"},
		},
	})
	brokerHandler := NewBrokerHandler(brokerSvc, sessionSvc)

	return NewRouter(RouterDeps{
		Pool:         integPool,
		Auth:         authSvc,
		Email:        emailSvc,
		OAuth:        oauthHandler,
		OAuth2:       oauth2Handler,
		Broker:       brokerHandler,
		Session:      sessionSvc,
		CookieDomain: "test.com",
		RDB:          integRDB,
		Limiter:      service.NewRateLimiter(integRDB),
		Audit:        service.NewAuditService(integPool),
		Webhook:      service.NewWebhookService(integPool),
	})
}

func integRequest(method, path string, body interface{}) *httptest.ResponseRecorder {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)
	return w
}

func cleanIntegDB(t interface {
	Context() context.Context
	Helper()
}) {
	t.Helper()
	ctx := context.Background()
	tables := []string{
		"federated_identities", "refresh_tokens", "email_verification_tokens",
		"password_reset_tokens", "clients", "client_redirect_uris", "users", "signing_keys",
		"fosite_requests", "access_tokens", "client_assertions",
		"audit_log", "webhooks", "mfa_recovery_codes", "client_post_logout_uris",
		"scope_grants", "role_scopes",
	}
	for _, table := range tables {
		_, _ = integPool.Exec(ctx, fmt.Sprintf("DELETE FROM auth.%s", table))
	}
	integMR.FlushAll()
}
