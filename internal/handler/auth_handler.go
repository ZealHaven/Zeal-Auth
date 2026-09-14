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
	config     *handlerConfig
}

type handlerConfig struct {
	CookieDomain string
}

func NewAuthHandler(auth *service.AuthService, email *service.EmailService, sessionSvc *service.SessionService) *AuthHandler {
	return &AuthHandler{auth: auth, email: email, sessionSvc: sessionSvc, config: &handlerConfig{}}
}

func (h *AuthHandler) SetCookieDomain(domain string) {
	h.config.CookieDomain = domain
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
		return
	}

	// Generate and send verification token
	if _, err := h.email.GenerateVerificationToken(r.Context(), result.User.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}

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

	result, err := h.auth.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidCredentials):
			writeError(w, http.StatusUnauthorized, "invalid_credentials")
		case errors.Is(err, service.ErrEmailNotVerified):
			writeError(w, http.StatusForbidden, "email_not_verified")
		case errors.Is(err, service.ErrSocialAccountOnly):
			writeError(w, http.StatusForbidden, "social_account_only")
		default:
			writeError(w, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	// Create session and set cookie
	if h.sessionSvc != nil {
		sess, err := h.sessionSvc.Create(r.Context(), result.User.ID.String(), "")
		if err == nil {
			service.SetSessionCookie(w, sess.ID, h.config.CookieDomain)
		}
	}

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
