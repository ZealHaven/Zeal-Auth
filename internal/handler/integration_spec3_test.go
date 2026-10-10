package handler

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zeal/auth/internal/service"
)

// ---- AC-3-3 / AC-SESSION-2: silent SSO across two clients ----

func TestE2E_SilentSSO_TwoClients(t *testing.T) {
	cleanIntegDB(t)
	seedSigningKey(t)

	clientA, secretA, uriA := "sso-app-a", "sso-secret-a-12345", "http://localhost:3001/callback"
	clientB, secretB, uriB := "sso-app-b", "sso-secret-b-12345", "http://localhost:3002/callback"
	guardEnsureClient(t, clientA, secretA, uriA)
	guardEnsureClient(t, clientB, secretB, uriB)

	email := "silent-sso@example.com"
	uid := createTestUser(t, email, "password123")
	verifyTestUser(t, uid)

	// Login once → session cookie (Flow C step 1)
	loginReq := httptest.NewRequest("POST", "/login", strings.NewReader(`{"email":"`+email+`","password":"password123"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginW := httptest.NewRecorder()
	integRouter.ServeHTTP(loginW, loginReq)
	sid := extractCookie(loginW)
	if sid == "" {
		t.Fatalf("no session cookie after login (status %d)", loginW.Code)
	}

	authorize := func(clientID, redirectURI string) *httptest.ResponseRecorder {
		t.Helper()
		challenge, _ := generatePKCE()
		q := url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {redirectURI},
			"scope":                 {"openid profile email"},
			"state":                 {"sso-state"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		req := httptest.NewRequest("GET", "/authorize?"+q.Encode(), nil)
		req.AddCookie(&http.Cookie{Name: service.SessionCookieName, Value: sid})
		w := httptest.NewRecorder()
		integRouter.ServeHTTP(w, req)
		return w
	}

	// Client 1: session → auto-issue code
	wA := authorize(clientA, uriA)
	locA := wA.Header().Get("Location")
	if !strings.HasPrefix(locA, uriA) || !strings.Contains(locA, "code=") {
		t.Fatalf("client A authorize: status=%d location=%q, want redirect to %s with code", wA.Code, locA, uriA)
	}

	// Client 2: same session → code immediately, no login screen (AC-3-3)
	wB := authorize(clientB, uriB)
	locB := wB.Header().Get("Location")
	if wB.Code == http.StatusFound && strings.HasPrefix(locB, "/login") {
		t.Fatal("silent SSO failed: client B authorize redirected to login despite valid session")
	}
	if !strings.HasPrefix(locB, uriB) || !strings.Contains(locB, "code=") {
		t.Fatalf("client B authorize: status=%d location=%q, want redirect to %s with code (no login prompt)", wB.Code, locB, uriB)
	}
}

// ---- AC-3-6 / AC-TOKEN-5: logout revokes refresh tokens ----

func TestE2E_Logout_RevokesRefreshToken(t *testing.T) {
	cleanIntegDB(t)
	seedSigningKey(t)

	clientID, clientSecret, redirectURI := "logout-revoke-app", "logout-revoke-secret-1", "http://localhost:9999/callback"
	guardEnsureClient(t, clientID, clientSecret, redirectURI)

	email := "logout-revoke@example.com"
	uid := createTestUser(t, email, "password123")
	verifyTestUser(t, uid)

	sid, code, verifier := guardAuthorize(t, email, "password123", clientID, redirectURI)
	resp := guardExchange(t, clientID, clientSecret, redirectURI, code, verifier)
	refresh, _ := resp["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("no refresh token: %v", resp)
	}

	// Seed another user's token BEFORE logout to prove the delete is subject-scoped
	seedOtherUserToken(t, "logout-other@example.com")

	// Logout (AC-3-6)
	logoutReq := httptest.NewRequest("GET", "/logout", nil)
	logoutReq.AddCookie(&http.Cookie{Name: service.SessionCookieName, Value: sid})
	logoutW := httptest.NewRecorder()
	integRouter.ServeHTTP(logoutW, logoutReq)
	if logoutW.Code != http.StatusFound {
		t.Fatalf("logout status = %d, want 302", logoutW.Code)
	}

	// Previously issued refresh token must be rejected at /token (AC-3-6, AC-TOKEN-5)
	refForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	postReq := httptest.NewRequest("POST", "/token", strings.NewReader(refForm.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postW := httptest.NewRecorder()
	integRouter.ServeHTTP(postW, postReq)
	if got := parseJSON(postW)["error"]; got != "invalid_grant" {
		t.Errorf("refresh after logout: error = %v, want invalid_grant (AC-3-6)", got)
	}

	// The subject-scoped delete must leave other users' tokens alone
	var n int
	_ = integPool.QueryRow(context.Background(),
		`SELECT count(*) FROM auth.fosite_requests WHERE key = 'refreshtoken:other-user-sig'`).Scan(&n)
	if n != 1 {
		t.Error("other user's refresh token was deleted by logout (delete not subject-scoped)")
	}
}

// seedOtherUserToken inserts a fosite refresh token row for a different user.
func seedOtherUserToken(t *testing.T, email string) {
	t.Helper()
	uid := createTestUser(t, email, "password123")
	if _, err := integPool.Exec(context.Background(),
		`INSERT INTO auth.fosite_requests (key, data)
		 VALUES ($1, jsonb_build_object('session_data', jsonb_build_object('subject', $2::text)))`,
		"refreshtoken:other-user-sig", uid); err != nil {
		t.Fatalf("seed other user token: %v", err)
	}
}

// ---- AC-3-2 / AC-3-7: reference client verifies ID token against JWKS ----

// jwksVerify checks an RS256 JWT signature against keys from /jwks.json using
// only stdlib crypto — this is the local-validation path products take.
func jwksVerify(token string, keys map[string]*rsa.PublicKey) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errNotJWT
	}
	var header struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return err
	}
	if err := json.Unmarshal(hdr, &header); err != nil {
		return err
	}
	if header.Alg != "RS256" {
		return errBadAlg
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	signing := []byte(parts[0] + "." + parts[1])
	digest := sha256.Sum256(signing)

	try := func(pub *rsa.PublicKey) error {
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig)
	}

	if pub, ok := keys[header.Kid]; ok && header.Kid != "" {
		return try(pub)
	}
	// kid absent or unknown: try every published key
	for _, pub := range keys {
		if err := try(pub); err == nil {
			return nil
		}
	}
	return errSignatureMismatch
}

var (
	errNotJWT            = &verifyErr{"not a JWT"}
	errBadAlg            = &verifyErr{"unsupported alg"}
	errSignatureMismatch = &verifyErr{"signature does not match any published key"}
)

type verifyErr struct{ msg string }

func (e *verifyErr) Error() string { return e.msg }

func fetchJWKS(t *testing.T) map[string]*rsa.PublicKey {
	t.Helper()
	req := httptest.NewRequest("GET", "/jwks.json", nil)
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("jwks status = %d", w.Code)
	}
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			t.Fatalf("decode n: %v", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			t.Fatalf("decode e: %v", err)
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}
	}
	if len(keys) == 0 {
		t.Fatal("JWKS published no keys")
	}
	return keys
}

func TestE2E_ReferenceClient_JWKSVerify(t *testing.T) {
	cleanIntegDB(t)
	seedSigningKey(t)

	clientID, clientSecret, redirectURI := "ref-client", "ref-client-secret-1", "http://localhost:9999/callback"
	guardEnsureClient(t, clientID, clientSecret, redirectURI)

	email := "ref-client@example.com"
	uid := createTestUser(t, email, "password123")
	verifyTestUser(t, uid)

	_, code, verifier := guardAuthorize(t, email, "password123", clientID, redirectURI)
	resp := guardExchange(t, clientID, clientSecret, redirectURI, code, verifier)
	idToken, _ := resp["id_token"].(string)
	if idToken == "" {
		t.Fatalf("no id_token: %v", resp)
	}

	// AC-3-2: verify locally against /jwks.json — no call back to the auth service
	keys := fetchJWKS(t)
	if err := jwksVerify(idToken, keys); err != nil {
		t.Errorf("ID token failed JWKS verification: %v (AC-3-2, AC-OIDC-3)", err)
	}

	// AC-3-7: flipped signature must fail
	parts := strings.Split(idToken, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	sig[0] ^= 0xFF
	tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
	if err := jwksVerify(tampered, keys); err == nil {
		t.Error("tampered signature verified successfully — must be rejected (AC-3-7)")
	}
}
