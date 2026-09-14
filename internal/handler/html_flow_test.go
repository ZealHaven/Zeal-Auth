package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSignupFlow_HTML_RedirectsToCheckEmail(t *testing.T) {
	h := setupHandlerTest(t)

	form := url.Values{}
	form.Set("email", "flow-test@example.com")
	form.Set("password", "password123")

	req := httptest.NewRequest("POST", "/signup-form", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.SignupForm(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusFound)
	}
	location := w.Header().Get("Location")
	if !strings.HasPrefix(location, "/check-email?email=") {
		t.Errorf("Location = %q, want /check-email?email=...", location)
	}
}

func TestVerifyFlow_HTML_ShowsSuccess(t *testing.T) {
	h := setupHandlerTest(t)
	ctx := context.Background()

	// Create user and verification token
	form := url.Values{}
	form.Set("email", "verify-flow@example.com")
	form.Set("password", "password123")

	req := httptest.NewRequest("POST", "/signup-form", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.SignupForm(w, req)

	// Insert a known token directly
	rawToken := "flow-verify-token-1234567890abcdef1234567890ab"
	hash := sha256Hex(rawToken)

	var userID string
	_ = testPool.QueryRow(ctx, `SELECT id FROM auth.users WHERE email = 'verify-flow@example.com'`).Scan(&userID)

	_, _ = testPool.Exec(ctx,
		`INSERT INTO auth.email_verification_tokens (user_id, token_hash, expires_at)
		 VALUES ($1, $2, now() + interval '24 hours')`, userID, hash)

	req = httptest.NewRequest("GET", "/verify?token="+rawToken, nil)
	w = httptest.NewRecorder()
	h.VerifyEmailPage(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "Email verified") {
		t.Error("response should contain success message")
	}
}

func TestLoginFlow_HTML_WithSession_CookieSet(t *testing.T) {
	h := setupHandlerTest(t)

	// Create user
	form := url.Values{}
	form.Set("email", "cookie-flow@example.com")
	form.Set("password", "password123")

	req := httptest.NewRequest("POST", "/signup-form", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.SignupForm(w, req)

	// Verify email
	_, _ = testPool.Exec(context.Background(), `UPDATE auth.users SET email_verified = true WHERE email = 'cookie-flow@example.com'`)

	// Login via form
	form2 := url.Values{}
	form2.Set("email", "cookie-flow@example.com")
	form2.Set("password", "password123")

	req = httptest.NewRequest("POST", "/login-form", strings.NewReader(form2.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.LoginForm(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestAuthorizeFlow_HTML_NoSession_ShowsRedirect(t *testing.T) {
	h := setupHandlerTest(t)

	req := httptest.NewRequest("GET", "/check-email?email=test@example.com", nil)
	w := httptest.NewRecorder()
	h.CheckEmailPage(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "test@example.com") {
		t.Error("check-email page should show the email")
	}
}
