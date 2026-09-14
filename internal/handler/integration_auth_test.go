package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestE2E_Signup_ValidCredentials(t *testing.T) {
	cleanIntegDB(t)

	body, _ := json.Marshal(map[string]string{
		"email":    "signup-e2e@example.com",
		"password": "password123",
	})

	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", w.Code, http.StatusCreated)
	}

	resp := parseJSON(w)
	if resp["message"] != "Account created. Check your email to verify." {
		t.Errorf("message = %q", resp["message"])
	}

	// Verify user was created in DB
	var count int
	_ = integPool.QueryRow(t.Context(),
		`SELECT count(*) FROM auth.users WHERE email = 'signup-e2e@example.com'`,
	).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 user, got %d", count)
	}
}

func TestE2E_Signup_DuplicateEmail(t *testing.T) {
	cleanIntegDB(t)

	body, _ := json.Marshal(map[string]string{
		"email":    "dup-e2e@example.com",
		"password": "password123",
	})

	// First signup
	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	// Second signup (duplicate)
	req = httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", w.Code, http.StatusConflict)
	}

	resp := parseJSON(w)
	if resp["error"] != "email_already_exists" {
		t.Errorf("error = %q", resp["error"])
	}
}

func TestE2E_Signup_WeakPassword(t *testing.T) {
	cleanIntegDB(t)

	body, _ := json.Marshal(map[string]string{
		"email":    "weak-e2e@example.com",
		"password": "short",
	})

	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	resp := parseJSON(w)
	if resp["error"] != "password_too_short" {
		t.Errorf("error = %q", resp["error"])
	}
}

func TestE2E_Signup_InvalidEmail(t *testing.T) {
	cleanIntegDB(t)

	body, _ := json.Marshal(map[string]string{
		"email":    "not-an-email",
		"password": "password123",
	})

	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	resp := parseJSON(w)
	if resp["error"] != "invalid_email" {
		t.Errorf("error = %q", resp["error"])
	}
}

func TestE2E_Signup_PasswordNotInResponse(t *testing.T) {
	cleanIntegDB(t)

	body, _ := json.Marshal(map[string]string{
		"email":    "password-leak@example.com",
		"password": "password123",
	})

	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	bodyBytes := w.Body.String()
	if bytes.Contains(w.Body.Bytes(), []byte("password123")) {
		t.Error("password should not appear in response")
	}
	_ = bodyBytes
}

func TestE2E_Login_CorrectCredentials(t *testing.T) {
	cleanIntegDB(t)

	// Create user
	uid := createTestUser(t, "login-e2e@example.com", "password123")
	verifyTestUser(t, uid)

	body, _ := json.Marshal(map[string]string{
		"email":    "login-e2e@example.com",
		"password": "password123",
	})

	req := httptest.NewRequest("POST", "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	resp := parseJSON(w)
	if resp["message"] != "Login successful" {
		t.Errorf("message = %q", resp["message"])
	}

	// Check session cookie
	cookie := extractCookie(w)
	if cookie == "" {
		t.Error("session cookie not set")
	}
}

func TestE2E_Login_WrongPassword(t *testing.T) {
	cleanIntegDB(t)

	uid := createTestUser(t, "wrongpw-e2e@example.com", "password123")
	verifyTestUser(t, uid)

	body, _ := json.Marshal(map[string]string{
		"email":    "wrongpw-e2e@example.com",
		"password": "wrongpassword",
	})

	req := httptest.NewRequest("POST", "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}

	resp := parseJSON(w)
	if resp["error"] != "invalid_credentials" {
		t.Errorf("error = %q", resp["error"])
	}
}

func TestE2E_Login_UnknownEmail_SameResponse(t *testing.T) {
	cleanIntegDB(t)

	// Login with unknown email should return same error as wrong password
	body, _ := json.Marshal(map[string]string{
		"email":    "unknown-e2e@example.com",
		"password": "password123",
	})

	req := httptest.NewRequest("POST", "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}

	resp := parseJSON(w)
	if resp["error"] != "invalid_credentials" {
		t.Errorf("error = %q, want invalid_credentials (user enumeration prevention)", resp["error"])
	}
}

func TestE2E_Login_UnverifiedEmail(t *testing.T) {
	cleanIntegDB(t)

	uid := createTestUser(t, "unverified-e2e@example.com", "password123")
	_ = uid // Don't verify

	body, _ := json.Marshal(map[string]string{
		"email":    "unverified-e2e@example.com",
		"password": "password123",
	})

	req := httptest.NewRequest("POST", "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}

	resp := parseJSON(w)
	if resp["error"] != "email_not_verified" {
		t.Errorf("error = %q", resp["error"])
	}
}
