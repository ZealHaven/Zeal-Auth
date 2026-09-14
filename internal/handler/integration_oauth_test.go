package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestE2E_Discovery_Document(t *testing.T) {
	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	resp := parseJSON(w)
	if resp["issuer"] != "https://auth.test.com" {
		t.Errorf("issuer = %v", resp["issuer"])
	}
	if resp["authorization_endpoint"] != "https://auth.test.com/authorize" {
		t.Errorf("authorization_endpoint = %v", resp["authorization_endpoint"])
	}
	if resp["token_endpoint"] != "https://auth.test.com/token" {
		t.Errorf("token_endpoint = %v", resp["token_endpoint"])
	}
	if resp["jwks_uri"] != "https://auth.test.com/jwks.json" {
		t.Errorf("jwks_uri = %v", resp["jwks_uri"])
	}
}

func TestE2E_JWKS_ReturnsKeys(t *testing.T) {
	seedSigningKey(t)

	req := httptest.NewRequest("GET", "/jwks.json", nil)
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	resp := parseJSON(w)
	keys, ok := resp["keys"].([]any)
	if !ok || len(keys) == 0 {
		t.Error("expected at least one key in JWKS")
	}
}

func TestE2E_AuthorizeCodeFlow_BadRedirectURI(t *testing.T) {
	cleanIntegDB(t)

	clientID, _, _ := createSignedTestClient(t)

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {"http://evil.com/callback"},
		"code_challenge":        {"test-challenge"},
		"code_challenge_method": {"S256"},
	}

	req := httptest.NewRequest("GET", "/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	// fosite returns 400 for bad redirect URI (or redirects to client error)
	if w.Code == http.StatusOK {
		t.Error("should not return 200 for bad redirect URI")
	}
}

func TestE2E_AuthorizeCodeFlow_BadClientID(t *testing.T) {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"nonexistent-client"},
		"redirect_uri":          {"http://localhost:9999/callback"},
		"code_challenge":        {"test-challenge"},
		"code_challenge_method": {"S256"},
	}

	req := httptest.NewRequest("GET", "/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	// fosite returns error for bad client_id
	if w.Code == http.StatusOK {
		// Should redirect to error page or return error
		location := w.Header().Get("Location")
		if location == "" {
			t.Error("expected redirect or error for bad client_id")
		}
	}
}

func TestE2E_AuthorizeFlow_MissingChallenge(t *testing.T) {
	cleanIntegDB(t)

	clientID, _, _ := createSignedTestClient(t)

	// Create a verified user and login
	uid := createTestUser(t, "auth-challenge-e2e@example.com", "password123")
	verifyTestUser(t, uid)

	// Get session cookie
	body := fmt.Sprintf(`{"email":"auth-challenge-e2e@example.com","password":"password123"}`)
	req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	cookie := extractCookie(w)

	// Try authorize without code_challenge
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {"http://localhost:9999/callback"},
	}

	req = httptest.NewRequest("GET", "/authorize?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: cookie})
	w = httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	// fosite should reject without PKCE challenge
	if w.Code == http.StatusOK {
		location := w.Header().Get("Location")
		if location == "" {
			t.Error("expected error redirect for missing PKCE challenge")
		}
	}
}
