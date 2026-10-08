package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/zeal/auth/internal/service"
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

// TestE2E_AuthorizeCodeFlow_HappyPath covers AC-2-1/2-2/2-3: full auth-code +
// PKCE exchange against Postgres-backed fosite storage, userinfo claims,
// refresh rotation, replay rejection.
func TestE2E_AuthorizeCodeFlow_HappyPath(t *testing.T) {
	cleanIntegDB(t)
	seedSigningKey(t)

	// Client with a REAL bcrypt secret — /token authenticates via bcrypt
	clientID, clientSecret, redirectURI := "happy-app", "happy-secret-12345", "http://localhost:9999/callback"
	hash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash client secret: %v", err)
	}
	if _, err := integPool.Exec(context.Background(),
		`INSERT INTO auth.clients (id, client_secret_hash, name) VALUES ($1, $2, $3)`,
		clientID, string(hash), "Happy App"); err != nil {
		t.Fatalf("insert client: %v", err)
	}
	if _, err := integPool.Exec(context.Background(),
		`INSERT INTO auth.client_redirect_uris (client_id, redirect_uri) VALUES ($1, $2)`,
		clientID, redirectURI); err != nil {
		t.Fatalf("insert redirect uri: %v", err)
	}

	email := "happy-e2e@example.com"
	uid := createTestUser(t, email, "password123")
	verifyTestUser(t, uid)

	// Login → session cookie
	loginReq := httptest.NewRequest("POST", "/login", strings.NewReader(`{"email":"`+email+`","password":"password123"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginW := httptest.NewRecorder()
	integRouter.ServeHTTP(loginW, loginReq)
	sid := extractCookie(loginW)
	if sid == "" {
		t.Fatalf("no session cookie after login (status %d, body %s)", loginW.Code, loginW.Body.String())
	}

	// Authorize with session + PKCE
	challenge, verifier := generatePKCE()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid profile email"},
		"state":                 {"happy-state-12345"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	authReq := httptest.NewRequest("GET", "/authorize?"+q.Encode(), nil)
	authReq.AddCookie(&http.Cookie{Name: service.SessionCookieName, Value: sid})
	authW := httptest.NewRecorder()
	integRouter.ServeHTTP(authW, authReq)
	if authW.Code != http.StatusFound && authW.Code != http.StatusSeeOther {
		t.Fatalf("authorize status = %d, want 302/303 (body %s)", authW.Code, authW.Body.String())
	}
	redir, err := url.Parse(authW.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	code := redir.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect: %s", redir.String())
	}
	if got := redir.Query().Get("state"); got != "happy-state-12345" {
		t.Errorf("state = %q", got)
	}

	// Exchange code → tokens
	tokForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"code_verifier": {verifier},
	}
	tokReq := httptest.NewRequest("POST", "/token", strings.NewReader(tokForm.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokW := httptest.NewRecorder()
	integRouter.ServeHTTP(tokW, tokReq)
	if tokW.Code != http.StatusOK {
		t.Fatalf("token status = %d, body = %s", tokW.Code, tokW.Body.String())
	}
	tok := parseJSON(tokW)
	access, _ := tok["access_token"].(string)
	refresh, _ := tok["refresh_token"].(string)
	idToken, _ := tok["id_token"].(string)
	if access == "" || refresh == "" || idToken == "" {
		t.Fatalf("missing tokens: access_set=%v refresh_set=%v id_set=%v", access != "", refresh != "", idToken != "")
	}
	if tok["scope"] != "openid profile email" {
		t.Errorf("scope = %v", tok["scope"])
	}

	// Userinfo claims
	uiReq := httptest.NewRequest("GET", "/userinfo", nil)
	uiReq.Header.Set("Authorization", "Bearer "+access)
	uiW := httptest.NewRecorder()
	integRouter.ServeHTTP(uiW, uiReq)
	if uiW.Code != http.StatusOK {
		t.Fatalf("userinfo status = %d, body = %s", uiW.Code, uiW.Body.String())
	}
	ui := parseJSON(uiW)
	if ui["email"] != email {
		t.Errorf("userinfo email = %v, want %s", ui["email"], email)
	}
	if ui["sub"] != uid {
		t.Errorf("userinfo sub = %v, want %s", ui["sub"], uid)
	}

	// Refresh rotation
	refForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	refReq := httptest.NewRequest("POST", "/token", strings.NewReader(refForm.Encode()))
	refReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refW := httptest.NewRecorder()
	integRouter.ServeHTTP(refW, refReq)
	if refW.Code != http.StatusOK {
		t.Fatalf("refresh status = %d, body = %s", refW.Code, refW.Body.String())
	}
	newRefresh, _ := parseJSON(refW)["refresh_token"].(string)
	if newRefresh == "" || newRefresh == refresh {
		t.Fatal("refresh token was not rotated")
	}

	// Old refresh token rejected
	oldReq := httptest.NewRequest("POST", "/token", strings.NewReader(refForm.Encode()))
	oldReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	oldW := httptest.NewRecorder()
	integRouter.ServeHTTP(oldW, oldReq)
	if got := parseJSON(oldW)["error"]; got != "invalid_grant" {
		t.Errorf("old refresh error = %v, want invalid_grant", got)
	}

	// Code replay → invalid_grant
	replayReq := httptest.NewRequest("POST", "/token", strings.NewReader(tokForm.Encode()))
	replayReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replayW := httptest.NewRecorder()
	integRouter.ServeHTTP(replayW, replayReq)
	if got := parseJSON(replayW)["error"]; got != "invalid_grant" {
		t.Errorf("replay error = %v, want invalid_grant", got)
	}
}

// ---- Guard tests: AC-AUTHZ-6, AC-AUTHZ-7, AC-TOKEN-2 ----

func guardEnsureClient(t *testing.T, id, secret, uri string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	_, err = integPool.Exec(context.Background(),
		`INSERT INTO auth.clients (id, client_secret_hash, name) VALUES ($1, $2, $3)
		 ON CONFLICT (id) DO UPDATE SET client_secret_hash = EXCLUDED.client_secret_hash`,
		id, string(hash), "Guard App")
	if err != nil {
		t.Fatalf("insert client: %v", err)
	}
	_, _ = integPool.Exec(context.Background(),
		`INSERT INTO auth.client_redirect_uris (client_id, redirect_uri) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		id, uri)
}

// guardAuthorize performs login + authorize and returns (sid, code, verifier).
func guardAuthorize(t *testing.T, email, password, clientID, redirectURI string) (string, string, string) {
	t.Helper()
	loginReq := httptest.NewRequest("POST", "/login", strings.NewReader(`{"email":"`+email+`","password":"`+password+`"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginW := httptest.NewRecorder()
	integRouter.ServeHTTP(loginW, loginReq)
	sid := extractCookie(loginW)
	if sid == "" {
		t.Fatalf("login failed: %d %s", loginW.Code, loginW.Body.String())
	}

	challenge, verifier := generatePKCE()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid profile email"},
		"state":                 {"guard-state-12345"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	authReq := httptest.NewRequest("GET", "/authorize?"+q.Encode(), nil)
	authReq.AddCookie(&http.Cookie{Name: service.SessionCookieName, Value: sid})
	authW := httptest.NewRecorder()
	integRouter.ServeHTTP(authW, authReq)
	redir, err := url.Parse(authW.Header().Get("Location"))
	if err != nil || redir.Query().Get("code") == "" {
		t.Fatalf("authorize failed: status=%d loc=%q", authW.Code, authW.Header().Get("Location"))
	}
	return sid, redir.Query().Get("code"), verifier
}

func guardExchange(t *testing.T, clientID, clientSecret, redirectURI, code, verifier string) map[string]any {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"code_verifier": {verifier},
	}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)
	return parseJSON(w)
}

func TestE2E_Token_Guards(t *testing.T) {
	cleanIntegDB(t)
	seedSigningKey(t)

	clientID, clientSecret, redirectURI := "guard-app", "guard-secret-12345", "http://localhost:9999/callback"
	guardEnsureClient(t, clientID, clientSecret, redirectURI)
	email := "guard-e2e@example.com"
	uid := createTestUser(t, email, "password123")
	verifyTestUser(t, uid)

	// AC-AUTHZ-6: wrong code_verifier → invalid_grant
	t.Run("AC-AUTHZ-6 wrong verifier", func(t *testing.T) {
		_, code, _ := guardAuthorize(t, email, "password123", clientID, redirectURI)
		resp := guardExchange(t, clientID, clientSecret, redirectURI, code, "wrong-verifier-0123456789012345678901234567")
		if resp["error"] != "invalid_grant" {
			t.Errorf("error = %v, want invalid_grant", resp["error"])
		}
	})

	// AC-AUTHZ-7: expired code → rejected
	t.Run("AC-AUTHZ-7 expired code", func(t *testing.T) {
		_, code, verifier := guardAuthorize(t, email, "password123", clientID, redirectURI)
		// Age stored authorize-code sessions 1h into the past (key = strategy signature, not raw code)
		res, err := integPool.Exec(context.Background(),
			`UPDATE auth.fosite_requests
			 SET data = jsonb_set(data, '{session_data,expires_at,authorize_code}', '"2020-01-01T00:00:00Z"'::jsonb)
			 WHERE key LIKE 'authcode:%'`)
		if err != nil {
			t.Fatalf("age code: %v", err)
		}
		if res.RowsAffected() == 0 {
			t.Fatal("no authcode rows aged")
		}
		resp := guardExchange(t, clientID, clientSecret, redirectURI, code, verifier)
		if resp["error"] != "invalid_grant" {
			t.Errorf("error = %v, want invalid_grant (body %v)", resp["error"], resp)
		}
	})

	// AC-TOKEN-2: access token past TTL → rejected by userinfo
	t.Run("AC-TOKEN-2 expired access token", func(t *testing.T) {
		_, code, verifier := guardAuthorize(t, email, "password123", clientID, redirectURI)
		resp := guardExchange(t, clientID, clientSecret, redirectURI, code, verifier)
		access, _ := resp["access_token"].(string)
		if access == "" {
			t.Fatalf("no access token: %v", resp)
		}
		// Age every stored access-token session 1h into the past
		if _, err := integPool.Exec(context.Background(),
			`UPDATE auth.fosite_requests
			 SET data = jsonb_set(data, '{session_data,expires_at,access_token}', '"2020-01-01T00:00:00Z"'::jsonb)
			 WHERE key LIKE 'accesstoken:%'`); err != nil {
			t.Fatalf("age access token: %v", err)
		}
		uiReq := httptest.NewRequest("GET", "/userinfo", nil)
		uiReq.Header.Set("Authorization", "Bearer "+access)
		uiW := httptest.NewRecorder()
		integRouter.ServeHTTP(uiW, uiReq)
		if uiW.Code != http.StatusUnauthorized {
			t.Errorf("userinfo status = %d, want 401 (body %s)", uiW.Code, uiW.Body.String())
		}
	})
}
