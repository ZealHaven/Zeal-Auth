package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/zeal/auth/internal/config"
	"github.com/zeal/auth/internal/db"
	"github.com/zeal/auth/internal/handler"
	"github.com/zeal/auth/internal/repository"
	"github.com/zeal/auth/internal/service"
)

func buildServer(cfg *config.Config) (http.Handler, func()) {
	ctx := context.Background()

	globalSecret := os.Getenv("FOSITE_GLOBAL_SECRET")
	keyEncKey := cfg.KeyEncryptionKey
	if cfg.Env == "prod" {
		// Fail fast: no dev fallbacks in prod
		if len(globalSecret) < 32 {
			log.Fatalf("FOSITE_GLOBAL_SECRET must be set to at least 32 bytes in prod")
		}
		if len(keyEncKey) != 64 {
			log.Fatalf("KEY_ENCRYPTION_KEY must be 64 hex chars (32 bytes) in prod")
		}
		if cfg.AdminToken == "" {
			log.Fatalf("ADMIN_TOKEN must be set in prod (client registry would be disabled)")
		}
	}
	if len(globalSecret) < 32 {
		globalSecret = "fosite-dev-secret-replace-in-prod-32bytes!!"
	}
	if keyEncKey == "" {
		// Dev fallback: .env.example ships KEY_ENCRYPTION_KEY empty; boot must
		// still work after `cp .env.example .env` (AC-3-4)
		keyEncKey = "0000000000000000000000000000000000000000000000000000000000000001"
	}
	cfg.KeyEncryptionKey = keyEncKey

	pool, err := db.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("db: %v", err)
	}

	if err := service.EnsureInitialKey(ctx, pool, cfg.JWTKID, cfg.KeyEncryptionKey); err != nil {
		log.Fatalf("ensure initial signing key: %v", err)
	}

	keySvc := service.NewKeyService(pool, cfg.KeyEncryptionKey)

	fositeCfg := handler.DefaultFositeConfig(
		"https://"+cfg.CookieDomain,
		cfg.CookieDomain,
	)
	fositeCfg.AdminToken = cfg.AdminToken
	fositeCfg.GlobalSecret = []byte(globalSecret)

	oauthHandler, err := handler.NewFositeServer(pool, keySvc, fositeCfg)
	if err != nil {
		log.Fatalf("fosite server: %v", err)
	}

	// go-redis needs a URL with scheme; bare host:port also accepted
	redisURL := cfg.RedisURL
	if !strings.Contains(redisURL, "://") {
		redisURL = "redis://" + redisURL
	}
	redisOpts, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Fatalf("redis url: %v", err)
	}
	rdb := redis.NewClient(redisOpts)
	sessionSvc := service.NewSessionService(rdb)

	oauth2Handler := handler.NewOAuth2Handler(oauthHandler, pool, keySvc, fositeCfg, sessionSvc)

	userRepo := repository.NewUserRepository(pool)
	verificationRepo := repository.NewVerificationRepository(pool)
	resetRepo := repository.NewResetRepository(pool)
	federatedRepo := repository.NewFederatedRepository(pool)
	authSvc := service.NewAuthService(userRepo)

	var mailer service.Mailer = service.LogMailer{}
	if cfg.EmailDriver == "smtp" {
		if cfg.SMTPHost == "" {
			log.Fatalf("EMAIL_DRIVER=smtp requires SMTP_HOST")
		}
		if cfg.EmailFrom == "" {
			log.Fatalf("EMAIL_DRIVER=smtp requires EMAIL_FROM")
		}
		mailer = service.SMTPMailer{
			Host:     cfg.SMTPHost,
			Port:     cfg.SMTPPort,
			User:     cfg.SMTPUser,
			Password: cfg.SMTPPass,
			From:     cfg.EmailFrom,
		}
	}
	publicURL := cfg.PublicURL
	if publicURL == "" {
		publicURL = "https://" + cfg.CookieDomain
	}
	emailSvc := service.NewEmailService(userRepo, verificationRepo, resetRepo, pool, sessionSvc, mailer, publicURL)

	googleOAuth := &oauth2.Config{
		ClientID:     cfg.GoogleClientID,
		ClientSecret: cfg.GoogleClientSecret,
		Endpoint:     google.Endpoint,
		RedirectURL:  cfg.GoogleRedirectURI,
		Scopes:       []string{"openid", "email", "profile"},
	}
	githubOAuth := &oauth2.Config{
		ClientID:     cfg.GitHubClientID,
		ClientSecret: cfg.GitHubClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://github.com/login/oauth/authorize",
			TokenURL: "https://github.com/login/oauth/access_token",
		},
		RedirectURL: cfg.GitHubRedirectURI,
		Scopes:      []string{"user:email"},
	}
	brokerSvc := service.NewBrokerService(service.BrokerDeps{
		Users:     userRepo,
		Federated: federatedRepo,
		RDB:       rdb,
		Google:    googleOAuth,
		GitHub:    githubOAuth,
	})
	brokerHandler := handler.NewBrokerHandler(brokerSvc, sessionSvc)

	router := handler.NewRouter(handler.RouterDeps{
		Pool:          pool,
		Auth:          authSvc,
		Email:         emailSvc,
		OAuth:         oauthHandler,
		OAuth2:        oauth2Handler,
		Broker:        brokerHandler,
		BrokerService: brokerSvc,
		Session:       sessionSvc,
		CookieDomain:  cfg.CookieDomain,
	})

	cleanup := func() {
		rdb.Close()
		pool.Close()
	}

	return router, cleanup
}

func main() {
	cfg := config.Load()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	router, cleanup := buildServer(cfg)
	defer cleanup()

	srv := &http.Server{
		Addr:         ":" + cfg.ServerPort,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("listening on :%s", cfg.ServerPort)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("shutdown: %v", err)
	}

	log.Println("stopped")
}
