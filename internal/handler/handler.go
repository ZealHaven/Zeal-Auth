package handler

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ory/fosite"
	"github.com/redis/go-redis/v9"

	"github.com/zeal/auth/internal/service"
)

type RouterDeps struct {
	Pool          *pgxpool.Pool
	Auth          *service.AuthService
	Email         *service.EmailService
	OAuth         *OAuthHandler
	OAuth2        *OAuth2Handler
	Broker        *BrokerHandler
	BrokerService *service.BrokerService
	Session       *service.SessionService
	CookieDomain  string
	RDB           *redis.Client           // Redis health ping (spec 4.2); nil = skip
	HSTS          bool                    // emit Strict-Transport-Security (prod behind TLS)
	Limiter       *service.RateLimiter    // brute-force throttling (spec 4.5); nil = off
	Audit         *service.AuditService   // spec 5.5 audit trail; nil = no-op
	Webhook       *service.WebhookService // spec 5.13 event webhooks; nil = no-op
}

func NewRouter(deps RouterDeps) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	})

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		if err := deps.Pool.Ping(r.Context()); err != nil {
			http.Error(w, "db unreachable", http.StatusServiceUnavailable)
			return
		}
		if deps.RDB != nil {
			if err := deps.RDB.Ping(r.Context()).Err(); err != nil {
				http.Error(w, "redis unreachable", http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Existing auth routes
	ah := NewAuthHandler(deps.Auth, deps.Email, deps.Session)
	ah.SetCookieDomain(deps.CookieDomain)
	ah.SetBroker(deps.BrokerService)
	ah.SetRateLimiter(deps.Limiter)
	ah.SetAudit(deps.Audit)
	ah.SetWebhook(deps.Webhook)
	mux.HandleFunc("POST /signup", ah.Signup)
	mux.HandleFunc("POST /login", ah.Login)
	mux.HandleFunc("GET /verify", ah.VerifyEmail)
	mux.HandleFunc("POST /forgot-password", ah.ForgotPassword)
	mux.HandleFunc("POST /reset-password", ah.ResetPassword)

	// HTML page routes
	mux.HandleFunc("GET /signup", ah.SignupPage)
	mux.HandleFunc("GET /login", ah.LoginPage)
	mux.HandleFunc("GET /forgot-password", ah.ForgotPasswordPage)
	mux.HandleFunc("GET /reset-password", ah.ResetPasswordPage)
	mux.HandleFunc("GET /check-email", ah.CheckEmailPage)
	// Spec 1 §5 URLs (3.9): both screen paths resolve to the same page
	mux.HandleFunc("GET /signup/check-email", ah.CheckEmailPage)
	mux.HandleFunc("GET /forgot-password/check-email", ah.CheckEmailPage)
	mux.HandleFunc("GET /link-account", func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, "link-account.html", map[string]string{
			"Provider": r.URL.Query().Get("provider"),
			"Email":    r.URL.Query().Get("email"),
			"Token":    r.URL.Query().Get("token"),
			"Error":    r.URL.Query().Get("error"),
		})
	})

	// HTML form submissions
	mux.HandleFunc("POST /signup-form", ah.SignupForm)
	mux.HandleFunc("POST /login-form", ah.LoginForm)
	mux.HandleFunc("POST /forgot-password-form", ah.ForgotPasswordForm)
	mux.HandleFunc("POST /reset-password-form", ah.ResetPasswordForm)

	// OAuth2/OIDC routes
	if deps.OAuth2 != nil {
		mux.HandleFunc("GET /authorize", deps.OAuth2.Authorize)
		mux.HandleFunc("GET /consent", deps.OAuth2.ConsentPage)
		mux.HandleFunc("POST /consent", deps.OAuth2.ConsentDecision)
		mux.HandleFunc("POST /token", rateIPMiddleware(deps.Limiter, "token", tokenLimit, tokenWindow, deps.OAuth2.Token))
		mux.HandleFunc("GET /userinfo", deps.OAuth2.UserInfo)
		mux.HandleFunc("GET /.well-known/openid-configuration", deps.OAuth2.Discovery)
		mux.HandleFunc("GET /jwks.json", deps.OAuth2.JWKS)
		mux.HandleFunc("GET /logout", deps.OAuth2.Logout)
		mux.HandleFunc("POST /revoke", deps.OAuth2.Revoke)
		mux.HandleFunc("POST /introspect", deps.OAuth2.Introspect)

		// spec 5.1: admin-token client create (legacy 2.5) + full admin dashboard
		mux.HandleFunc("POST /admin/clients", deps.OAuth2.CreateClient)
	}

	// Admin dashboard (spec 5.1–5.4): every route fail-closed behind requireAdmin.
	adm := NewAdminHandler(deps.Pool, deps.Session, deps.Audit)
	adminToken := ""
	var introspect func(ctx context.Context, token string) string
	if deps.OAuth2 != nil && deps.OAuth2.config != nil {
		adminToken = deps.OAuth2.config.AdminToken
		if deps.OAuth2.oauth != nil {
			// Bearer access-token admin path (spec 5.16, AC-5-12).
			introspect = func(ctx context.Context, token string) string {
				sess := &openidSession{}
				_, _, err := deps.OAuth2.oauth.fosite.IntrospectToken(ctx, token, fosite.AccessToken, sess)
				if err != nil {
					return ""
				}
				return sess.Subject
			}
		}
	}
	gate := func(next http.HandlerFunc) http.HandlerFunc {
		return requireAdmin(deps.Pool, deps.Session, adminToken, introspect, next)
	}
	mux.HandleFunc("GET /admin", gate(adm.Dashboard))
	mux.HandleFunc("GET /admin/users", gate(adm.ListUsers))
	mux.HandleFunc("POST /admin/users/{id}/verify", gate(func(w http.ResponseWriter, r *http.Request) {
		adm.VerifyUser(w, r, r.PathValue("id"))
	}))
	mux.HandleFunc("POST /admin/users/{id}/disable", gate(func(w http.ResponseWriter, r *http.Request) {
		adm.DisableUser(w, r, r.PathValue("id"))
	}))
	mux.HandleFunc("POST /admin/users/{id}/force-reset", gate(func(w http.ResponseWriter, r *http.Request) {
		adm.ForcePasswordReset(w, r, r.PathValue("id"))
	}))
	mux.HandleFunc("GET /admin/users/{id}/sessions", gate(func(w http.ResponseWriter, r *http.Request) {
		adm.ListUserSessions(w, r, r.PathValue("id"))
	}))
	mux.HandleFunc("POST /admin/users/{id}/logout", gate(func(w http.ResponseWriter, r *http.Request) {
		adm.RevokeUserSessions(w, r, r.PathValue("id"))
	}))
	mux.HandleFunc("GET /admin/clients", gate(adm.ListClients))
	mux.HandleFunc("POST /admin/clients/{id}/disable", gate(func(w http.ResponseWriter, r *http.Request) {
		adm.DisableClient(w, r, r.PathValue("id"))
	}))
	mux.HandleFunc("GET /admin/webhooks", gate(adm.ListWebhooks))
	mux.HandleFunc("POST /admin/webhooks", gate(adm.CreateWebhook))
	mux.HandleFunc("POST /admin/webhooks/{id}/disable", gate(func(w http.ResponseWriter, r *http.Request) {
		adm.DisableWebhook(w, r, r.PathValue("id"))
	}))

	// Developer self-service portal (spec 5.14, AC-5-10), session-gated.
	portal := NewPortalHandler(deps.Pool, deps.Audit)
	mux.HandleFunc("GET /portal", requireSession(deps.Session, portal.Page))
	mux.HandleFunc("POST /portal/clients", requireSession(deps.Session, func(w http.ResponseWriter, r *http.Request, userID string) {
		portal.CreateClient(w, r, userID)
	}))
	mux.HandleFunc("POST /portal/clients/{id}/rotate", requireSession(deps.Session, func(w http.ResponseWriter, r *http.Request, userID string) {
		portal.RotateSecret(w, r, userID, r.PathValue("id"))
	}))

	// Dynamic Client Registration (spec 5.15, AC-5-11) — opt-in via
	// DCR_SOFTWARE_STATEMENT_SECRET; 403 when unset.
	dcr := NewDCRHandler(deps.Pool, deps.Audit)
	mux.HandleFunc("POST /register", dcr.Register)

	// MFA (spec 5.6): step-up completion + settings (session-gated).
	mfa := NewMfaHandler(deps.Pool, deps.Session, deps.Audit)
	mux.HandleFunc("POST /login/totp", func(w http.ResponseWriter, r *http.Request) {
		mfa.CompleteLogin(w, r, deps.CookieDomain)
	})
	mux.HandleFunc("POST /settings/mfa/setup", requireSession(deps.Session, func(w http.ResponseWriter, r *http.Request, userID string) {
		var email string
		_ = deps.Pool.QueryRow(r.Context(), `SELECT email FROM auth.users WHERE id = $1`, userID).Scan(&email)
		mfa.Setup(w, r, userID, email)
	}))
	mux.HandleFunc("POST /settings/mfa/verify", requireSession(deps.Session, func(w http.ResponseWriter, r *http.Request, userID string) {
		mfa.Verify(w, r, userID)
	}))
	mux.HandleFunc("POST /settings/mfa/disable", requireSession(deps.Session, func(w http.ResponseWriter, r *http.Request, userID string) {
		mfa.Disable(w, r, userID)
	}))

	// Self-service (spec 5.7 sessions + 5.9 profile), session-gated.
	prof := NewProfileHandler(deps.Pool, deps.Session, deps.Audit)
	mux.HandleFunc("GET /api/sessions", requireSession(deps.Session, prof.ListSessions))
	mux.HandleFunc("DELETE /api/sessions/{id}", requireSession(deps.Session, func(w http.ResponseWriter, r *http.Request, userID string) {
		prof.RevokeSession(w, r, userID, r.PathValue("id"))
	}))
	mux.HandleFunc("GET /api/profile", requireSession(deps.Session, prof.Get))
	mux.HandleFunc("POST /api/profile/password", requireSession(deps.Session, func(w http.ResponseWriter, r *http.Request, userID string) {
		prof.ChangePassword(w, r, userID)
	}))
	mux.HandleFunc("POST /api/profile/unlink", requireSession(deps.Session, func(w http.ResponseWriter, r *http.Request, userID string) {
		prof.UnlinkIdentity(w, r, userID)
	}))
	// HTML profile page (spec 5.9).
	mux.HandleFunc("GET /profile", requireSession(deps.Session, prof.Page))
	mux.HandleFunc("POST /profile/password-form", requireSession(deps.Session, func(w http.ResponseWriter, r *http.Request, userID string) {
		prof.ChangePasswordForm(w, r, userID)
	}))
	mux.HandleFunc("POST /profile/sessions/{id}/revoke", requireSession(deps.Session, func(w http.ResponseWriter, r *http.Request, userID string) {
		prof.RevokeSessionForm(w, r, userID, r.PathValue("id"))
	}))

	// Federation broker routes
	if deps.Broker != nil {
		mux.HandleFunc("GET /oauth/google", deps.Broker.GoogleInitiate)
		mux.HandleFunc("GET /oauth/google/callback", deps.Broker.GoogleCallback)
		mux.HandleFunc("GET /oauth/github", deps.Broker.GitHubInitiate)
		mux.HandleFunc("GET /oauth/github/callback", deps.Broker.GitHubCallback)
	}

	return withMiddleware(mux, deps.HSTS)
}
