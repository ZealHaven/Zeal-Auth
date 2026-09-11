package handler

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zeal/auth/internal/service"
)

type RouterDeps struct {
	Pool      *pgxpool.Pool
	Auth      *service.AuthService
	Email     *service.EmailService
	OAuth     *OAuthHandler
	OAuth2    *OAuth2Handler
	Broker    *BrokerHandler
}

func NewRouter(deps RouterDeps) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		if err := deps.Pool.Ping(r.Context()); err != nil {
			http.Error(w, "db unreachable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Existing auth routes
	ah := NewAuthHandler(deps.Auth, deps.Email)
	mux.HandleFunc("POST /signup", ah.Signup)
	mux.HandleFunc("POST /login", ah.Login)
	mux.HandleFunc("GET /verify", ah.VerifyEmail)
	mux.HandleFunc("POST /forgot-password", ah.ForgotPassword)
	mux.HandleFunc("POST /reset-password", ah.ResetPassword)

	// OAuth2/OIDC routes
	if deps.OAuth2 != nil {
		mux.HandleFunc("GET /authorize", deps.OAuth2.Authorize)
		mux.HandleFunc("POST /token", deps.OAuth2.Token)
		mux.HandleFunc("GET /userinfo", deps.OAuth2.UserInfo)
		mux.HandleFunc("GET /.well-known/openid-configuration", deps.OAuth2.Discovery)
		mux.HandleFunc("GET /jwks.json", deps.OAuth2.JWKS)
		mux.HandleFunc("GET /logout", deps.OAuth2.Logout)
		mux.HandleFunc("POST /admin/clients", deps.OAuth2.CreateClient)
	}

	// Federation broker routes
	if deps.Broker != nil {
		mux.HandleFunc("GET /oauth/google", deps.Broker.GoogleInitiate)
		mux.HandleFunc("GET /oauth/google/callback", deps.Broker.GoogleCallback)
		mux.HandleFunc("GET /oauth/github", deps.Broker.GitHubInitiate)
		mux.HandleFunc("GET /oauth/github/callback", deps.Broker.GitHubCallback)
	}

	return mux
}
