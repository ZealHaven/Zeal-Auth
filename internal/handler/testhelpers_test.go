package handler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/zeal/auth/internal/repository"
	"github.com/zeal/auth/internal/service"
)

func createTestUser(t *testing.T, email, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	userRepo := repository.NewUserRepository(integPool)
	result, err := userRepo.Create(context.Background(), email, string(hash))
	if err != nil {
		t.Fatalf("create test user: %v", err)
	}
	return result.ID.String()
}

func verifyTestUser(t *testing.T, userID string) {
	t.Helper()
	_, err := integPool.Exec(context.Background(),
		`UPDATE auth.users SET email_verified = true WHERE id = $1`, userID)
	if err != nil {
		t.Fatalf("verify test user: %v", err)
	}
}

func createTestClient(t *testing.T, id, secret string, uris []string) {
	t.Helper()
	hash := "$2a$10$fakehash"
	_, err := integPool.Exec(context.Background(),
		`INSERT INTO auth.clients (id, client_secret_hash, name) VALUES ($1, $2, $3)
		 ON CONFLICT (id) DO UPDATE SET name = $3`,
		id, hash, "Test Client",
	)
	if err != nil {
		t.Fatalf("create test client: %v", err)
	}
	for _, uri := range uris {
		_, _ = integPool.Exec(context.Background(),
			`INSERT INTO auth.client_redirect_uris (client_id, redirect_uri) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			id, uri,
		)
	}
}

func makeRequest(method, path string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, body)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)
	return w
}

func parseJSON(resp *httptest.ResponseRecorder) map[string]any {
	var result map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return result
}

func extractCookie(resp *httptest.ResponseRecorder) string {
	cookies := resp.Result().Cookies()
	for _, c := range cookies {
		if c.Name == service.SessionCookieName {
			return c.Value
		}
	}
	return ""
}

func generatePKCE() (challenge, verifier string) {
	b := make([]byte, 32)
	_, _ = fmt.Fprint(io.Discard) // avoid unused import
	for i := range b {
		b[i] = byte(i)
	}
	verifier = base64.RawURLEncoding.EncodeToString(b[:32])
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return challenge, verifier
}

func createSignedTestClient(t *testing.T) (clientID, clientSecret, redirectURI string) {
	t.Helper()
	clientID = "test-app"
	clientSecret = "test-secret-12345"
	redirectURI = "http://localhost:9999/callback"
	createTestClient(t, clientID, clientSecret, []string{redirectURI})
	return
}

func insertUser(t *testing.T, email, passwordHash string, verified bool) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := integPool.QueryRow(context.Background(),
		`INSERT INTO auth.users (email, password_hash, email_verified)
		 VALUES ($1, $2, $3) RETURNING id`,
		email, passwordHash, verified,
	).Scan(&id)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	return id
}

func getUserByEmail(email string) (id, passwordHash string, verified bool) {
	_ = integPool.QueryRow(context.Background(),
		`SELECT id, COALESCE(password_hash, ''), email_verified FROM auth.users WHERE email = $1`,
		email,
	).Scan(&id, &passwordHash, &verified)
	return
}

func seedSigningKey(t *testing.T) {
	t.Helper()
	_ = service.EnsureInitialKey(context.Background(), integPool, "test-key-1", testEncKey)
}

func waitForAsync() {
	time.Sleep(10 * time.Millisecond)
}

// Query helpers for DB assertions
func countRows(table, condition string, args ...any) int {
	var count int
	query := fmt.Sprintf("SELECT count(*) FROM auth.%s WHERE %s", table, condition)
	_ = integPool.QueryRow(context.Background(), query, args...).Scan(&count)
	return count
}

func getTokenFromDB(t *testing.T, table, column, value string) string {
	t.Helper()
	var token string
	err := integPool.QueryRow(context.Background(),
		fmt.Sprintf("SELECT token_hash FROM auth.%s WHERE %s = $1 LIMIT 1", table, column), value,
	).Scan(&token)
	if err != nil && err != pgx.ErrNoRows {
		t.Fatalf("query token: %v", err)
	}
	return token
}
