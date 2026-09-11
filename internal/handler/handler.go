package handler

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zeal/auth/internal/service"
)

func NewRouter(pool *pgxpool.Pool, auth *service.AuthService, email *service.EmailService) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		if err := pool.Ping(r.Context()); err != nil {
			http.Error(w, "db unreachable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	ah := NewAuthHandler(auth, email)
	mux.HandleFunc("POST /signup", ah.Signup)
	mux.HandleFunc("POST /login", ah.Login)
	mux.HandleFunc("GET /verify", ah.VerifyEmail)
	mux.HandleFunc("POST /forgot-password", ah.ForgotPassword)
	mux.HandleFunc("POST /reset-password", ah.ResetPassword)

	return mux
}
