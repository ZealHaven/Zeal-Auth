package handler

import (
	"context"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/handler/pkce"
	"github.com/ory/fosite/token/hmac"
	"github.com/ory/fosite/token/jwt"

	"github.com/zeal/auth/internal/service"
	authstorage "github.com/zeal/auth/internal/storage"
)

// FositeConfig holds fosite-specific configuration.
type FositeConfig struct {
	Issuer               string
	AuthCodeLifespan     time.Duration
	AccessTokenLifespan  time.Duration
	RefreshTokenLifespan time.Duration
	IDTokenLifespan      time.Duration
	EnforcePKCE          bool
	MinParameterEntropy  int
	CookieDomain         string
	GlobalSecret         []byte
	AdminToken           string // required for /admin/* routes; empty = all admin requests rejected
}

func DefaultFositeConfig(issuer, cookieDomain string) *FositeConfig {
	return &FositeConfig{
		Issuer:               issuer,
		AuthCodeLifespan:     5 * time.Minute,
		AccessTokenLifespan:  15 * time.Minute,
		RefreshTokenLifespan: 720 * time.Hour, // 30 days
		IDTokenLifespan:      1 * time.Hour,
		EnforcePKCE:          true,
		MinParameterEntropy:  8,
		CookieDomain:         cookieDomain,
		GlobalSecret:         []byte("fosite-dev-secret-replace-in-prod-32bytes"),
	}
}

// OAuthHandler holds all OAuth2-related dependencies.
type OAuthHandler struct {
	fosite fosite.OAuth2Provider
	pool   *pgxpool.Pool
	keySvc *service.KeyService
	config *FositeConfig
}

// NewFositeServer creates a fully configured fosite.OAuth2Provider with all
// handlers wired for Authorization Code + PKCE, OIDC, and refresh tokens.
func NewFositeServer(pool *pgxpool.Pool, keySvc *service.KeyService, cfg *FositeConfig) (*OAuthHandler, error) {
	store := authstorage.NewFositeStorage(pool)

	config := &fosite.Config{
		AccessTokenLifespan:            cfg.AccessTokenLifespan,
		RefreshTokenLifespan:           cfg.RefreshTokenLifespan,
		AuthorizeCodeLifespan:          cfg.AuthCodeLifespan,
		IDTokenLifespan:                cfg.IDTokenLifespan,
		IDTokenIssuer:                  cfg.Issuer,
		EnforcePKCE:                    cfg.EnforcePKCE,
		EnforcePKCEForPublicClients:    true,
		EnablePKCEPlainChallengeMethod: false,
		MinParameterEntropy:            cfg.MinParameterEntropy,
		AllowedPromptValues:            []string{"login", "none"},
		ScopeStrategy:                  fosite.WildcardScopeStrategy,
		AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
		RefreshTokenScopes:             []string{}, // issue refresh tokens regardless of scope
		TokenURL:                       cfg.Issuer + "/token",
		GlobalSecret:                   cfg.GlobalSecret,
		// RedirectSecureChecker left nil → fosite.IsRedirectURISecure
		// (https anywhere, http only for localhost/loopback)
	}

	// HMAC strategy for opaque tokens (auth codes, refresh tokens, access tokens)
	hmacStrat := oauth2.NewHMACSHAStrategy(
		&hmac.HMACStrategy{Config: config},
		config,
	)

	// JWT signer for OIDC ID tokens
	jwtSigner := &jwt.DefaultSigner{
		GetPrivateKey: func(_ context.Context) (interface{}, error) {
			return keySvc.GetActivePrivateKey(context.Background())
		},
	}

	oidcStrategy := &openid.DefaultStrategy{
		Signer: jwtSigner,
		Config: config,
	}

	// Build provider by registering handlers on config, then creating provider
	config.AuthorizeEndpointHandlers = fosite.AuthorizeEndpointHandlers{}
	config.TokenEndpointHandlers = fosite.TokenEndpointHandlers{}
	config.RevocationHandlers = fosite.RevocationHandlers{}
	config.TokenIntrospectionHandlers = fosite.TokenIntrospectionHandlers{}

	// 1. Authorize Code + Token (explicit grant)
	authCodeHandler := &oauth2.AuthorizeExplicitGrantHandler{
		AccessTokenStrategy:    hmacStrat,
		RefreshTokenStrategy:   hmacStrat,
		AuthorizeCodeStrategy:  hmacStrat,
		CoreStorage:            store,
		TokenRevocationStorage: store, // required for replay revocation
		Config:                 config,
	}
	config.AuthorizeEndpointHandlers.Append(authCodeHandler)
	config.TokenEndpointHandlers.Append(authCodeHandler)

	// 2. Refresh Token Grant
	refreshHandler := &oauth2.RefreshTokenGrantHandler{
		AccessTokenStrategy:    hmacStrat,
		RefreshTokenStrategy:   hmacStrat,
		TokenRevocationStorage: store,
		Config:                 config,
	}
	config.TokenEndpointHandlers.Append(refreshHandler)

	// 2b. Client Credentials Grant — service-to-service tokens (spec 5.11).
	config.TokenEndpointHandlers.Append(&oauth2.ClientCredentialsGrantHandler{
		HandleHelper: &oauth2.HandleHelper{
			AccessTokenStrategy: hmacStrat,
			AccessTokenStorage:  store,
			Config:              config,
		},
		Config: config,
	})

	// 3. PKCE
	pkceHandler := &pkce.Handler{
		AuthorizeCodeStrategy: hmacStrat,
		Storage:               store,
		Config:                config,
	}
	config.AuthorizeEndpointHandlers.Append(pkceHandler)
	config.TokenEndpointHandlers.Append(pkceHandler)

	// 4. OpenID Connect (appended AFTER authorize code handler)
	oidcHandler := &openid.OpenIDConnectExplicitHandler{
		OpenIDConnectRequestStorage: store,
		IDTokenHandleHelper: &openid.IDTokenHandleHelper{
			IDTokenStrategy: oidcStrategy,
		},
		OpenIDConnectRequestValidator: openid.NewOpenIDConnectRequestValidator(jwtSigner, config),
		Config:                        config,
	}
	config.AuthorizeEndpointHandlers.Append(oidcHandler)
	config.TokenEndpointHandlers.Append(oidcHandler)

	// 5. OpenID Connect Refresh (issues new ID token on refresh)
	config.TokenEndpointHandlers.Append(&openid.OpenIDConnectRefreshHandler{
		IDTokenHandleHelper: &openid.IDTokenHandleHelper{
			IDTokenStrategy: oidcStrategy,
		},
		Config: config,
	})

	// 6. Token Revocation
	config.RevocationHandlers.Append(&oauth2.TokenRevocationHandler{
		TokenRevocationStorage: store,
		AccessTokenStrategy:    hmacStrat,
		RefreshTokenStrategy:   hmacStrat,
	})

	// 7. Token Introspection
	config.TokenIntrospectionHandlers.Append(&oauth2.CoreValidator{
		CoreStrategy: hmacStrat,
		CoreStorage:  store,
		Config:       config,
	})

	provider := fosite.NewOAuth2Provider(store, config)

	return &OAuthHandler{
		fosite: provider,
		pool:   pool,
		keySvc: keySvc,
		config: cfg,
	}, nil
}

// GetPrivateKey returns the RSA private key for JWT signing.
func (oh *OAuthHandler) GetPrivateKey(ctx context.Context) (*rsa.PrivateKey, error) {
	return oh.keySvc.GetActivePrivateKey(ctx)
}

// EnsurePrivateKey is a helper to extract RSA private key.
func EnsurePrivateKey(ctx context.Context, ks *service.KeyService) (*rsa.PrivateKey, error) {
	priv, err := ks.GetActivePrivateKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("get private key: %w", err)
	}
	return priv, nil
}
