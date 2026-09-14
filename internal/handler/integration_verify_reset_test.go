package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zeal/auth/internal/service"
)

func TestE2E_Verify_ValidToken(t *testing.T) {
	cleanIntegDB(t)

	// Signup
	body, _ := json.Marshal(map[string]string{
		"email":    "verify-e2e@example.com",
		"password": "password123",
	})
	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("signup status = %d", w.Code)
	}

	// Insert verification token
	rawToken := "e2e-verify-token-valid-1234567890abcdef"
	tokenHash := hashTokenForTest(rawToken)

	var userID string
	_ = integPool.QueryRow(t.Context(),
		`SELECT id FROM auth.users WHERE email = 'verify-e2e@example.com'`,
	).Scan(&userID)

	_, _ = integPool.Exec(t.Context(),
		`INSERT INTO auth.email_verification_tokens (user_id, token_hash, expires_at)
		 VALUES ($1, $2, now() + interval '24 hours')`, userID, tokenHash)

	// Verify
	req = httptest.NewRequest("GET", "/verify?token="+rawToken, nil)
	w = httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	resp := parseJSON(w)
	if resp["message"] != "Email verified successfully" {
		t.Errorf("message = %q", resp["message"])
	}

	// Verify user is now verified
	var verified bool
	_ = integPool.QueryRow(t.Context(),
		`SELECT email_verified FROM auth.users WHERE id = $1`, userID,
	).Scan(&verified)
	if !verified {
		t.Error("user should be email_verified after verification")
	}
}

func TestE2E_Verify_ExpiredToken(t *testing.T) {
	cleanIntegDB(t)

	uid := createTestUser(t, "expired-verify-e2e@example.com", "password123")

	rawToken := "e2e-verify-token-expired-1234567890abcdef"
	tokenHash := hashTokenForTest(rawToken)

	_, _ = integPool.Exec(t.Context(),
		`INSERT INTO auth.email_verification_tokens (user_id, token_hash, expires_at)
		 VALUES ($1, $2, now() - interval '1 hour')`, uid, tokenHash)

	req := httptest.NewRequest("GET", "/verify?token="+rawToken, nil)
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	if w.Code != http.StatusGone {
		t.Errorf("status = %d, want %d", w.Code, http.StatusGone)
	}

	resp := parseJSON(w)
	if resp["error"] != "token_expired" {
		t.Errorf("error = %q", resp["error"])
	}
}

func TestE2E_Verify_AlreadyUsed(t *testing.T) {
	cleanIntegDB(t)

	uid := createTestUser(t, "used-verify-e2e@example.com", "password123")

	rawToken := "e2e-verify-token-used-1234567890abcdef"
	tokenHash := hashTokenForTest(rawToken)

	_, _ = integPool.Exec(t.Context(),
		`INSERT INTO auth.email_verification_tokens (user_id, token_hash, expires_at, used_at)
		 VALUES ($1, $2, now() + interval '24 hours', now())`, uid, tokenHash)

	req := httptest.NewRequest("GET", "/verify?token="+rawToken, nil)
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	resp := parseJSON(w)
	if resp["message"] != "Email already verified" {
		t.Errorf("message = %q", resp["message"])
	}
}

func TestE2E_ForgotPassword_Registered(t *testing.T) {
	cleanIntegDB(t)

	createTestUser(t, "forgot-e2e@example.com", "password123")

	body, _ := json.Marshal(map[string]string{
		"email": "forgot-e2e@example.com",
	})

	req := httptest.NewRequest("POST", "/forgot-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	resp := parseJSON(w)
	if resp["message"] != "If an account exists, a reset link has been sent." {
		t.Errorf("message = %q", resp["message"])
	}

	// Verify reset token was created
	var count int
	_ = integPool.QueryRow(t.Context(),
		`SELECT count(*) FROM auth.password_reset_tokens WHERE user_id = (
			SELECT id FROM auth.users WHERE email = 'forgot-e2e@example.com'
		)`,
	).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 reset token, got %d", count)
	}
}

func TestE2E_ForgotPassword_Unregistered(t *testing.T) {
	cleanIntegDB(t)

	body, _ := json.Marshal(map[string]string{
		"email": "nobody-e2e@example.com",
	})

	req := httptest.NewRequest("POST", "/forgot-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	// Same response for unregistered (user enumeration prevention)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	resp := parseJSON(w)
	if resp["message"] != "If an account exists, a reset link has been sent." {
		t.Errorf("message = %q", resp["message"])
	}
}

func TestE2E_ResetPassword_Success(t *testing.T) {
	cleanIntegDB(t)

	uid := createTestUser(t, "reset-e2e@example.com", "password123")

	rawToken := "e2e-reset-token-valid-1234567890abcdef"
	tokenHash := hashTokenForTest(rawToken)

	_, _ = integPool.Exec(t.Context(),
		`INSERT INTO auth.password_reset_tokens (user_id, token_hash, expires_at)
		 VALUES ($1, $2, now() + interval '60 minutes')`, uid, tokenHash)

	body, _ := json.Marshal(map[string]string{
		"token":    rawToken,
		"password": "newsecurepass123",
	})

	req := httptest.NewRequest("POST", "/reset-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	resp := parseJSON(w)
	if resp["message"] != "Password updated successfully" {
		t.Errorf("message = %q", resp["message"])
	}
}

func TestE2E_ResetPassword_RevokesTokens(t *testing.T) {
	cleanIntegDB(t)

	uid := createTestUser(t, "revoke-e2e@example.com", "password123")

	// Create the test client (needed for FK constraint on refresh_tokens)
	createTestClient(t, "test-app", "test-secret", []string{"http://localhost/callback"})

	// Create refresh tokens for the user
	_, _ = integPool.Exec(t.Context(),
		`INSERT INTO auth.refresh_tokens (user_id, token_hash, client_id, family_id, expires_at)
		 VALUES ($1, 'token-hash-1', 'test-app', gen_random_uuid(), now() + interval '1 day'),
		        ($1, 'token-hash-2', 'test-app', gen_random_uuid(), now() + interval '1 day')`, uid)

	rawToken := "e2e-reset-token-revoke-1234567890abcdef"
	tokenHash := hashTokenForTest(rawToken)

	_, _ = integPool.Exec(t.Context(),
		`INSERT INTO auth.password_reset_tokens (user_id, token_hash, expires_at)
		 VALUES ($1, $2, now() + interval '60 minutes')`, uid, tokenHash)

	body, _ := json.Marshal(map[string]string{
		"token":    rawToken,
		"password": "newsecurepass123",
	})

	req := httptest.NewRequest("POST", "/reset-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	// Verify refresh tokens are revoked
	var revokedCount int
	_ = integPool.QueryRow(t.Context(),
		`SELECT count(*) FROM auth.refresh_tokens WHERE user_id = $1 AND revoked_at IS NOT NULL`, uid,
	).Scan(&revokedCount)
	if revokedCount != 2 {
		t.Errorf("expected 2 revoked tokens, got %d", revokedCount)
	}
}

func TestE2E_ResetPassword_InvalidToken(t *testing.T) {
	cleanIntegDB(t)

	body, _ := json.Marshal(map[string]string{
		"token":    "nonexistent-token",
		"password": "newsecurepass123",
	})

	req := httptest.NewRequest("POST", "/reset-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	resp := parseJSON(w)
	if resp["error"] != "invalid_token" {
		t.Errorf("error = %q", resp["error"])
	}
}

func TestE2E_ResetPassword_ExpiredToken(t *testing.T) {
	cleanIntegDB(t)

	uid := createTestUser(t, "expired-reset-e2e@example.com", "password123")

	rawToken := "e2e-reset-token-expired-1234567890abcdef"
	tokenHash := hashTokenForTest(rawToken)

	_, _ = integPool.Exec(t.Context(),
		`INSERT INTO auth.password_reset_tokens (user_id, token_hash, expires_at)
		 VALUES ($1, $2, now() - interval '1 hour')`, uid, tokenHash)

	body, _ := json.Marshal(map[string]string{
		"token":    rawToken,
		"password": "newsecurepass123",
	})

	req := httptest.NewRequest("POST", "/reset-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	resp := parseJSON(w)
	if resp["error"] != "token_expired" {
		t.Errorf("error = %q", resp["error"])
	}
}

func hashTokenForTest(token string) string {
	h := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", h)
}

func TestE2E_ResetPassword_RevokesSessions(t *testing.T) {
	cleanIntegDB(t)

	uid := createTestUser(t, "session-revoke-e2e@example.com", "password123")

	// Create session for user
	sessionSvc := service.NewSessionService(integRDB)
	sess, err := sessionSvc.Create(t.Context(), uid, "test-app")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Reset password
	rawToken := "e2e-reset-token-session-revoke-1234567890ab"
	tokenHash := hashTokenForTest(rawToken)

	_, _ = integPool.Exec(t.Context(),
		`INSERT INTO auth.password_reset_tokens (user_id, token_hash, expires_at)
		 VALUES ($1, $2, now() + interval '60 minutes')`, uid, tokenHash)

	body, _ := json.Marshal(map[string]string{
		"token":    rawToken,
		"password": "newsecurepass123",
	})

	req := httptest.NewRequest("POST", "/reset-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	// Verify session is deleted
	got, _ := sessionSvc.Get(t.Context(), sess.ID)
	if got != nil {
		t.Error("session should be deleted after password reset")
	}
}
