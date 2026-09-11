package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestVerifyHandler_200(t *testing.T) {
	h := setupHandlerTest(t)
	ctx := context.Background()

	// Create user and verification token
	body, _ := json.Marshal(map[string]string{
		"email":    "verify@example.com",
		"password": "password123",
	})
	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Signup(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("signup status = %d, want %d", w.Code, http.StatusCreated)
	}

	// Insert a known token directly
	rawToken := "test-verify-token-1234567890abcdef1234567890ab"
	hash := sha256Hex(rawToken)

	var userID string
	_ = testPool.QueryRow(ctx, `SELECT id FROM auth.users WHERE email = 'verify@example.com'`).Scan(&userID)

	_, _ = testPool.Exec(ctx,
		`INSERT INTO auth.email_verification_tokens (user_id, token_hash, expires_at)
		 VALUES ($1, $2, now() + interval '24 hours')`, userID, hash)

	req = httptest.NewRequest("GET", "/verify?token="+rawToken, nil)
	w = httptest.NewRecorder()
	h.VerifyEmail(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["message"] != "Email verified successfully" {
		t.Errorf("message = %q", resp["message"])
	}
}

func TestVerifyHandler_200_AlreadyVerified(t *testing.T) {
	h := setupHandlerTest(t)
	ctx := context.Background()

	rawToken := "already-used-token-1234567890abcdef1234567890ab"
	hash := sha256Hex(rawToken)

	_, _ = testPool.Exec(ctx, `DELETE FROM auth.users WHERE email = 'already@example.com'`)
	_, _ = testPool.Exec(ctx,
		`INSERT INTO auth.users (email, password_hash, email_verified)
		 VALUES ('already@example.com', '$2a$10$fakehash', true)`)
	var userID string
	_ = testPool.QueryRow(ctx, `SELECT id FROM auth.users WHERE email = 'already@example.com'`).Scan(&userID)

	now := time.Now()
	_, _ = testPool.Exec(ctx,
		`INSERT INTO auth.email_verification_tokens (user_id, token_hash, expires_at, used_at)
		 VALUES ($1, $2, now() + interval '24 hours', $3)`, userID, hash, now)

	req := httptest.NewRequest("GET", "/verify?token="+rawToken, nil)
	w := httptest.NewRecorder()
	h.VerifyEmail(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["message"] != "Email already verified" {
		t.Errorf("message = %q", resp["message"])
	}
}

func TestVerifyHandler_400_InvalidToken(t *testing.T) {
	h := setupHandlerTest(t)

	req := httptest.NewRequest("GET", "/verify?token=nonexistent", nil)
	w := httptest.NewRecorder()
	h.VerifyEmail(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "invalid_token" {
		t.Errorf("error = %q", resp["error"])
	}
}

func TestVerifyHandler_410_Expired(t *testing.T) {
	h := setupHandlerTest(t)
	ctx := context.Background()

	rawToken := "expired-verify-token-1234567890abcdef1234567890ab"
	hash := sha256Hex(rawToken)

	_, _ = testPool.Exec(ctx, `DELETE FROM auth.users WHERE email = 'expired@example.com'`)
	_, _ = testPool.Exec(ctx,
		`INSERT INTO auth.users (email, password_hash, email_verified)
		 VALUES ('expired@example.com', '$2a$10$fakehash', false)`)
	var userID string
	_ = testPool.QueryRow(ctx, `SELECT id FROM auth.users WHERE email = 'expired@example.com'`).Scan(&userID)

	_, _ = testPool.Exec(ctx,
		`INSERT INTO auth.email_verification_tokens (user_id, token_hash, expires_at)
		 VALUES ($1, $2, now() - interval '1 hour')`, userID, hash)

	req := httptest.NewRequest("GET", "/verify?token="+rawToken, nil)
	w := httptest.NewRecorder()
	h.VerifyEmail(w, req)

	if w.Code != http.StatusGone {
		t.Errorf("status = %d, want %d", w.Code, http.StatusGone)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "token_expired" {
		t.Errorf("error = %q", resp["error"])
	}
}

func TestForgotPasswordHandler_200(t *testing.T) {
	h := setupHandlerTest(t)

	body, _ := json.Marshal(map[string]string{
		"email": "forgot@example.com",
	})

	req := httptest.NewRequest("POST", "/forgot-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ForgotPassword(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["message"] != "If an account exists, a reset link has been sent." {
		t.Errorf("message = %q", resp["message"])
	}
}

func TestResetPasswordHandler_200(t *testing.T) {
	h := setupHandlerTest(t)
	ctx := context.Background()

	// Create user
	_, _ = testPool.Exec(ctx, `DELETE FROM auth.users WHERE email = 'resethandler@example.com'`)
	_, _ = testPool.Exec(ctx,
		`INSERT INTO auth.users (email, password_hash, email_verified)
		 VALUES ('resethandler@example.com', '$2a$10$fakehash', true)`)
	var userID string
	_ = testPool.QueryRow(ctx, `SELECT id FROM auth.users WHERE email = 'resethandler@example.com'`).Scan(&userID)

	rawToken := "reset-handler-token-1234567890abcdef1234567890ab"
	hash := sha256Hex(rawToken)

	_, _ = testPool.Exec(ctx,
		`INSERT INTO auth.password_reset_tokens (user_id, token_hash, expires_at)
		 VALUES ($1, $2, now() + interval '60 minutes')`, userID, hash)

	body, _ := json.Marshal(map[string]string{
		"token":    rawToken,
		"password": "newsecurepass123",
	})

	req := httptest.NewRequest("POST", "/reset-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ResetPassword(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["message"] != "Password updated successfully" {
		t.Errorf("message = %q", resp["message"])
	}
}

func TestResetPasswordHandler_400(t *testing.T) {
	h := setupHandlerTest(t)

	body, _ := json.Marshal(map[string]string{
		"token":    "nonexistent-token",
		"password": "newsecurepass123",
	})

	req := httptest.NewRequest("POST", "/reset-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ResetPassword(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "invalid_token" {
		t.Errorf("error = %q", resp["error"])
	}
}
