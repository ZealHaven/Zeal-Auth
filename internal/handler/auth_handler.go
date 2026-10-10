package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/zeal/auth/internal/service"
)

type AuthHandler struct {
	auth       *service.AuthService
	email      *service.EmailService
	sessionSvc *service.SessionService
	broker     *service.BrokerService
	config     *handlerConfig
	limiter    *service.RateLimiter    // spec 4.5; nil = rate limiting off
	audit      *service.AuditService   // spec 5.5; nil = no-op
	webhook    *service.WebhookService // spec 5.13; nil = no-op
}

type handlerConfig struct {
	CookieDomain string
}

func NewAuthHandler(auth *service.AuthService, email *service.EmailService, sessionSvc *service.SessionService) *AuthHandler {
	return &AuthHandler{auth: auth, email: email, sessionSvc: sessionSvc, config: &handlerConfig{}}
}

// SetRateLimiter enables brute-force throttling (spec 4.5).
func (h *AuthHandler) SetRateLimiter(l *service.RateLimiter) {
	h.limiter = l
}

// SetAudit enables the spec-5.5 audit trail (nil-safe).
func (h *AuthHandler) SetAudit(a *service.AuditService) { h.audit = a }

// SetWebhook enables spec-5.13 event dispatch (nil-safe).
func (h *AuthHandler) SetWebhook(w *service.WebhookService) { h.webhook = w }

func (h *AuthHandler) SetCookieDomain(domain string) {
	h.config.CookieDomain = domain
}

// SetBroker enables completing a pending social-account link during login.
func (h *AuthHandler) SetBroker(b *service.BrokerService) {
	h.broker = b
}

type signupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type forgotPasswordRequest struct {
	Email string `json:"email"`
}

type resetPasswordRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, errMsg string) {
	writeJSON(w, status, map[string]string{"error": errMsg})
}

func (h *AuthHandler) Signup(w http.ResponseWriter, r *http.Request) {
	var req signupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}

	if secs, ok := rateBlocked(r.Context(), h.limiter, r, "signup", req.Email, generalLimit); ok {
		writeRateLimited(w, secs)
		return
	}

	result, err := h.auth.Signup(r.Context(), req.Email, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidEmail):
			writeError(w, http.StatusBadRequest, "invalid_email")
		case errors.Is(err, service.ErrPasswordTooShort):
			writeError(w, http.StatusBadRequest, "password_too_short")
		case errors.Is(err, service.ErrEmailAlreadyExists):
			writeError(w, http.StatusConflict, "email_already_exists")
		default:
			writeError(w, http.StatusInternalServerError, "internal_error")
		}
		// Count failed attempts (spec 4.5)
		rateHit(r.Context(), h.limiter, r, "signup", req.Email, generalLimit, generalWindow)
		return
	}

	// Generate and send verification token
	if _, err := h.email.GenerateVerificationToken(r.Context(), result.User.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	uid := result.User.ID.String()
	h.audit.Log(r.Context(), uid, "signup", uid, clientIP(r), nil)
	// spec 5.13 / AC-5-9: fire user.created once the account exists.
	h.webhook.Dispatch(r.Context(), service.EventUserCreated, uid, map[string]any{
		"user_id": uid,
		"email":   result.User.Email,
	})

	writeJSON(w, http.StatusCreated, map[string]string{
		"message": "Account created. Check your email to verify.",
	})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}

	if secs, ok := rateBlocked(r.Context(), h.limiter, r, "login", req.Email, loginLimit); ok {
		writeRateLimited(w, secs)
		return
	}

	result, err := h.auth.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidCredentials):
			writeError(w, http.StatusUnauthorized, "invalid_credentials")
		case errors.Is(err, service.ErrEmailNotVerified):
			writeError(w, http.StatusForbidden, "email_not_verified")
		case errors.Is(err, service.ErrSocialAccountOnly):
			writeError(w, http.StatusForbidden, "social_account_only")
		case errors.Is(err, service.ErrAccountDisabled):
			writeError(w, http.StatusForbidden, "account_disabled")
		default:
			writeError(w, http.StatusInternalServerError, "internal_error")
		}
		// Count failed attempts toward lockout (spec 4.5, AC-4-3)
		rateHit(r.Context(), h.limiter, r, "login", req.Email, loginLimit, loginWindow)
		return
	}
	rateReset(r.Context(), h.limiter, "login", req.Email)

	// Spec 5.6 step-up: TOTP enabled → issue pending challenge, no session yet.
	if result.User.TOTPEnabled && h.sessionSvc != nil {
		token, err := h.sessionSvc.CreatePendingMFA(r.Context(), result.User.ID.String())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error")
			return
		}
		h.audit.Log(r.Context(), result.User.ID.String(), "login.mfa_required", result.User.ID.String(), clientIP(r), nil)
		if isHTMLRequest(r) {
			renderTemplate(w, "mfa.html", map[string]string{"Token": token})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"mfa_required": true, "mfa_token": token})
		return
	}

	// Create session and set cookie
	if h.sessionSvc != nil {
		sess, err := h.sessionSvc.Create(r.Context(), result.User.ID.String(), "")
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error")
			return
		}
		service.SetSessionCookie(w, sess.ID, h.config.CookieDomain)
	}
	h.audit.Log(r.Context(), result.User.ID.String(), "login", result.User.ID.String(), clientIP(r), nil)

	writeJSON(w, http.StatusOK, map[string]any{
		"message": "Login successful",
		"user_id": result.User.ID.String(),
	})
}

func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		if isHTMLRequest(r) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		writeError(w, http.StatusBadRequest, "missing_token")
		return
	}

	msg, status, err := h.email.VerifyEmail(r.Context(), token)

	// HTML path
	if isHTMLRequest(r) {
		if err != nil {
			switch {
			case errors.Is(err, service.ErrTokenExpired):
				renderTemplate(w, "verify-expired.html", map[string]string{})
			default:
				renderTemplate(w, "login.html", map[string]string{
					"Error": "Invalid verification link",
				})
			}
			return
		}
		renderTemplate(w, "verify-success.html", map[string]string{})
		return
	}

	// JSON path
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidToken):
			writeError(w, status, "invalid_token")
		case errors.Is(err, service.ErrTokenExpired):
			writeError(w, status, "token_expired")
		default:
			writeError(w, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	writeJSON(w, status, map[string]string{"message": msg})
}

func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req forgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}

	if secs, ok := rateBlocked(r.Context(), h.limiter, r, "reset", req.Email, generalLimit); ok {
		writeRateLimited(w, secs)
		return
	}
	rateHit(r.Context(), h.limiter, r, "reset", req.Email, generalLimit, generalWindow)

	msg, status, err := h.email.ForgotPassword(r.Context(), req.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	writeJSON(w, status, map[string]string{"message": msg})
}

func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req resetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}

	if secs, ok := rateBlocked(r.Context(), h.limiter, r, "reset", clientIP(r), generalLimit); ok {
		writeRateLimited(w, secs)
		return
	}
	rateHit(r.Context(), h.limiter, r, "reset", clientIP(r), generalLimit, generalWindow)

	msg, status, err := h.email.ResetPassword(r.Context(), req.Token, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidToken):
			writeError(w, status, "invalid_token")
		case errors.Is(err, service.ErrTokenExpired):
			writeError(w, status, "token_expired")
		case errors.Is(err, service.ErrTokenAlreadyUsed):
			writeError(w, status, "token_already_used")
		case errors.Is(err, service.ErrPasswordTooShort):
			writeError(w, status, "password_too_short")
		default:
			writeError(w, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	writeJSON(w, status, map[string]string{"message": msg})
}

// Helper to parse UUID from query string
func parseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}
