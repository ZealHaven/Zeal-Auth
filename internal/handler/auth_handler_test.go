package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zeal/auth/internal/repository"
	"github.com/zeal/auth/internal/service"
)

var testPool *pgxpool.Pool

func testDBURL() string {
	if url := os.Getenv("DATABASE_URL"); url != "" {
		return url
	}
	return "postgres://auth:auth@localhost:5435/auth?sslmode=disable"
}

func TestMain(m *testing.M) {
	ctx := context.Background()
	var err error
	testPool, err = pgxpool.New(ctx, testDBURL())
	if err != nil {
		panic("connect pool: " + err.Error())
	}

	// Run migrations
	_, _ = testPool.Exec(ctx, "DROP SCHEMA IF EXISTS auth CASCADE")
	_, _ = testPool.Exec(ctx, "DROP TABLE IF EXISTS public.schema_migrations")
	_, _ = testPool.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS auth")
	out, _ := os.ReadFile("../../migrations/000001_init.up.sql")
	if out != nil {
		_, err = testPool.Exec(ctx, string(out))
		if err != nil {
			panic("run migration: " + err.Error())
		}
	}

	code := m.Run()

	_, _ = testPool.Exec(ctx, "DROP SCHEMA IF EXISTS auth CASCADE")
	_, _ = testPool.Exec(ctx, "DROP TABLE IF EXISTS public.schema_migrations")
	testPool.Close()
	os.Exit(code)
}

func setupHandlerTest(t *testing.T) *AuthHandler {
	t.Helper()
	if testPool == nil {
		t.Fatal("testPool not initialized")
	}
	// Clean users table
	_, _ = testPool.Exec(context.Background(), "DELETE FROM auth.users")

	userRepo := repository.NewUserRepository(testPool)
	authSvc := service.NewAuthService(userRepo)
	return NewAuthHandler(authSvc)
}

func TestSignupHandler_201(t *testing.T) {
	h := setupHandlerTest(t)

	body, _ := json.Marshal(map[string]string{
		"email":    "signup@example.com",
		"password": "password123",
	})

	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Signup(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", w.Code, http.StatusCreated)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["message"] != "Account created. Check your email to verify." {
		t.Errorf("message = %q", resp["message"])
	}
}

func TestSignupHandler_409_Duplicate(t *testing.T) {
	h := setupHandlerTest(t)

	body, _ := json.Marshal(map[string]string{
		"email":    "dup@example.com",
		"password": "password123",
	})

	// First signup
	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Signup(w, req)

	// Second signup (duplicate)
	req = httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.Signup(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", w.Code, http.StatusConflict)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "email_already_exists" {
		t.Errorf("error = %q, want %q", resp["error"], "email_already_exists")
	}
}

func TestSignupHandler_400_Validation(t *testing.T) {
	h := setupHandlerTest(t)

	tests := []struct {
		name  string
		email string
		pass  string
	}{
		{"invalid email", "not-an-email", "password123"},
		{"short password", "valid@example.com", "short"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{
				"email":    tt.email,
				"password": tt.pass,
			})

			req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.Signup(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestLoginHandler_200(t *testing.T) {
	h := setupHandlerTest(t)

	// Create user
	body, _ := json.Marshal(map[string]string{
		"email":    "login@example.com",
		"password": "password123",
	})
	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Signup(w, req)

	// Verify email directly
	_, _ = testPool.Exec(context.Background(), `UPDATE auth.users SET email_verified = true WHERE email = 'login@example.com'`)

	// Login
	req = httptest.NewRequest("POST", "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.Login(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["message"] != "Login successful" {
		t.Errorf("message = %q", resp["message"])
	}
	if _, ok := resp["user_id"]; !ok {
		t.Error("missing user_id in response")
	}
}

func TestLoginHandler_401(t *testing.T) {
	h := setupHandlerTest(t)

	body, _ := json.Marshal(map[string]string{
		"email":    "wrong@example.com",
		"password": "wrongpassword",
	})

	req := httptest.NewRequest("POST", "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Login(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestLoginHandler_403_Unverified(t *testing.T) {
	h := setupHandlerTest(t)

	// Create user
	body, _ := json.Marshal(map[string]string{
		"email":    "unverified@example.com",
		"password": "password123",
	})
	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Signup(w, req)

	// Login without verifying
	req = httptest.NewRequest("POST", "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.Login(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "email_not_verified" {
		t.Errorf("error = %q, want %q", resp["error"], "email_not_verified")
	}
}
