package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/zeal/auth/internal/service"
)

func isHTMLRequest(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/html") || strings.Contains(accept, "*/*") {
		return true
	}
	if r.Method == http.MethodGet && accept == "" {
		// Bare GET with no Accept header: check if it looks like a browser navigation
		// (has a Referer or User-Agent from a browser)
		referer := r.Header.Get("Referer")
		userAgent := r.Header.Get("User-Agent")
		return referer != "" || strings.Contains(userAgent, "Mozilla")
	}
	contentType := r.Header.Get("Content-Type")
	return strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/x-www-form-urlencoded")
}

func (h *AuthHandler) SignupPage(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "signup.html", map[string]string{})
}

func (h *AuthHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")
	renderTemplate(w, "login.html", map[string]string{
		"ReturnTo": returnTo,
	})
}

func (h *AuthHandler) ForgotPasswordPage(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "forgot-password.html", map[string]bool{
		"Success": false,
	})
}

func (h *AuthHandler) ResetPasswordPage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	renderTemplate(w, "reset-password.html", map[string]string{
		"Token": token,
	})
}

func (h *AuthHandler) SignupForm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderTemplate(w, "signup.html", map[string]string{"Error": "Invalid form data"})
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	if secs, ok := rateBlocked(r.Context(), h.limiter, r, "signup", email, generalLimit); ok {
		writeHTMLRateLimited(w, secs)
		renderTemplate(w, "signup.html", map[string]string{"Error": "Too many attempts. Try again later."})
		return
	}

	result, err := h.auth.Signup(r.Context(), email, password)
	if err != nil {
		rateHit(r.Context(), h.limiter, r, "signup", email, generalLimit, generalWindow)
		var errMsg string
		switch {
		case errors.Is(err, service.ErrInvalidEmail):
			errMsg = "Please enter a valid email address"
		case errors.Is(err, service.ErrPasswordTooShort):
			errMsg = "Password must be at least 8 characters"
		case errors.Is(err, service.ErrEmailAlreadyExists):
			errMsg = "An account with this email already exists"
		default:
			errMsg = "Something went wrong. Please try again."
		}
		renderTemplate(w, "signup.html", map[string]string{
			"Email": email,
			"Error": errMsg,
		})
		return
	}

	// Generate and send verification token
	if _, err := h.email.GenerateVerificationToken(r.Context(), result.User.ID); err != nil {
		renderTemplate(w, "signup.html", map[string]string{
			"Email": email,
			"Error": "Something went wrong. Please try again.",
		})
		return
	}

	http.Redirect(w, r, "/signup/check-email?email="+url.QueryEscape(email), http.StatusFound)
}

func (h *AuthHandler) LoginForm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderTemplate(w, "login.html", map[string]string{"Error": "Invalid form data"})
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	returnTo := r.FormValue("return_to")

	if secs, ok := rateBlocked(r.Context(), h.limiter, r, "login", email, loginLimit); ok {
		writeHTMLRateLimited(w, secs)
		renderTemplate(w, "login.html", map[string]string{
			"Email": email, "Error": "Too many attempts. Try again later.", "ReturnTo": returnTo,
		})
		return
	}

	result, err := h.auth.Login(r.Context(), email, password)
	if err != nil {
		rateHit(r.Context(), h.limiter, r, "login", email, loginLimit, loginWindow)
		var errMsg string
		switch {
		case errors.Is(err, service.ErrInvalidCredentials):
			errMsg = "Invalid email or password"
		case errors.Is(err, service.ErrEmailNotVerified):
			errMsg = "Please verify your email first"
		case errors.Is(err, service.ErrSocialAccountOnly):
			errMsg = "This account uses social login. Please use Google or GitHub."
		default:
			errMsg = "Something went wrong. Please try again."
		}
		renderTemplate(w, "login.html", map[string]string{
			"Email":    email,
			"Error":    errMsg,
			"ReturnTo": returnTo,
		})
		return
	}

	// Complete pending social-account link before issuing a session
	if token := r.FormValue("link_token"); token != "" {
		if h.broker == nil {
			renderTemplate(w, "login.html", map[string]string{
				"Email": email, "Error": "Something went wrong. Please try again.", "ReturnTo": returnTo,
			})
			return
		}
		linkTo, err := h.broker.CompleteLink(r.Context(), token, result.User)
		if err != nil {
			msg := "Could not link account. Please try signing in with the provider again."
			if errors.Is(err, service.ErrLinkEmailMismatch) {
				msg = "This password belongs to a different email address."
			}
			renderTemplate(w, "link-account.html", map[string]string{
				"Provider": r.FormValue("provider"),
				"Email":    email,
				"Token":    token,
				"Error":    msg,
			})
			return
		}
		returnTo = linkTo
	}

	// Spec 5.6: TOTP step-up before a session is issued.
	if result.User.TOTPEnabled && h.sessionSvc != nil {
		token, err := h.sessionSvc.CreatePendingMFA(r.Context(), result.User.ID.String())
		if err != nil {
			renderTemplate(w, "login.html", map[string]string{
				"Email": email, "Error": "Something went wrong. Please try again.", "ReturnTo": returnTo,
			})
			return
		}
		rateReset(r.Context(), h.limiter, "login", email)
		renderTemplate(w, "mfa.html", map[string]string{"Token": token})
		return
	}

	// Create session and set cookie
	if h.sessionSvc != nil {
		sess, err := h.sessionSvc.Create(r.Context(), result.User.ID.String(), "")
		if err != nil {
			renderTemplate(w, "login.html", map[string]string{
				"Email":    email,
				"Error":    "Something went wrong. Please try again.",
				"ReturnTo": returnTo,
			})
			return
		}
		service.SetSessionCookie(w, sess.ID, h.config.CookieDomain)
	}
	rateReset(r.Context(), h.limiter, "login", email)

	if returnTo != "" {
		http.Redirect(w, r, returnTo, http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"message": "Login successful",
		"user_id": result.User.ID.String(),
	})
}

func (h *AuthHandler) CheckEmailPage(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	renderTemplate(w, "check-email.html", map[string]string{
		"Email": email,
	})
}

func (h *AuthHandler) ForgotPasswordForm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderTemplate(w, "forgot-password.html", map[string]bool{"Success": false})
		return
	}

	email := r.FormValue("email")

	if secs, ok := rateBlocked(r.Context(), h.limiter, r, "reset", email, generalLimit); ok {
		writeHTMLRateLimited(w, secs)
		renderTemplate(w, "forgot-password.html", map[string]any{
			"Success": false, "Error": "Too many attempts. Try again later.",
		})
		return
	}
	rateHit(r.Context(), h.limiter, r, "reset", email, generalLimit, generalWindow)

	_, _, _ = h.email.ForgotPassword(r.Context(), email)

	renderTemplate(w, "forgot-password.html", map[string]any{
		"Success": true,
		"Email":   email,
	})
}

func (h *AuthHandler) ResetPasswordForm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderTemplate(w, "reset-password.html", map[string]string{"Error": "Invalid form data"})
		return
	}

	token := r.FormValue("token")
	password := r.FormValue("password")

	_, _, err := h.email.ResetPassword(r.Context(), token, password)
	if err != nil {
		var errMsg string
		switch {
		case errors.Is(err, service.ErrInvalidToken):
			errMsg = "Invalid or expired reset link"
		case errors.Is(err, service.ErrTokenExpired):
			errMsg = "This reset link has expired. Request a new one."
		case errors.Is(err, service.ErrTokenAlreadyUsed):
			errMsg = "This reset link has already been used"
		case errors.Is(err, service.ErrPasswordTooShort):
			errMsg = "Password must be at least 8 characters"
		default:
			errMsg = "Something went wrong. Please try again."
		}
		renderTemplate(w, "reset-password.html", map[string]string{
			"Token": token,
			"Error": errMsg,
		})
		return
	}

	renderTemplate(w, "reset-password.html", map[string]bool{
		"Success": true,
	})
}

func (h *AuthHandler) VerifyEmailPage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	_, _, err := h.email.VerifyEmail(r.Context(), token)
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
}
