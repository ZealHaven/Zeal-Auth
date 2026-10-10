package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	cristalhq "github.com/cristalhq/jwt/v4"
	"github.com/ory/fosite"

	"github.com/zeal/auth/internal/service"
)

// ---- helpers ----

func loginAs(t *testing.T, email, password string) string {
	t.Helper()
	req := httptest.NewRequest("POST", "/login",
		strings.NewReader(`{"email":"`+email+`","password":"`+password+`"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login %s: status=%d body=%s", email, w.Code, w.Body.String())
	}
	sid := extractCookie(w)
	if sid == "" {
		t.Fatalf("no sid cookie for %s", email)
	}
	return sid
}

func withSession(sid string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.AddCookie(&http.Cookie{Name: service.SessionCookieName, Value: sid})
		next(w, r)
	}
}

func makeUser(t *testing.T, email, role string) (uid, password string) {
	t.Helper()
	password = "password123"
	uid = createTestUser(t, email, password)
	verifyTestUser(t, uid)
	if role != "" {
		_, err := integPool.Exec(context.Background(),
			`UPDATE auth.users SET role = $1 WHERE id = $2`, role, uid)
		if err != nil {
			t.Fatalf("set role: %v", err)
		}
	}
	return uid, password
}

// ---- AC-5-1: admin gating ----

func TestE2E_Admin_ForbiddenForNonAdmin(t *testing.T) {
	cleanIntegDB(t)
	_, pw := makeUser(t, "nonadmin@example.com", "")
	sid := loginAs(t, "nonadmin@example.com", pw)

	req := httptest.NewRequest("GET", "/admin", nil)
	req.AddCookie(&http.Cookie{Name: service.SessionCookieName, Value: sid})
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-admin GET /admin: status=%d, want 403", w.Code)
	}
}

func TestE2E_Admin_ShowsDashboardForAdmin(t *testing.T) {
	cleanIntegDB(t)
	_, pw := makeUser(t, "boss@example.com", "admin")
	sid := loginAs(t, "boss@example.com", pw)

	req := httptest.NewRequest("GET", "/admin", nil)
	req.AddCookie(&http.Cookie{Name: service.SessionCookieName, Value: sid})
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("admin GET /admin: status=%d, want 200", w.Code)
	}
}

// ---- AC-5-2: client disable invalidates tokens ----

func TestE2E_Admin_DisableClientInvalidatesTokens(t *testing.T) {
	cleanIntegDB(t)
	seedSigningKey(t)

	clientID, clientSecret, redirectURI := "disable-app", "disable-secret-999", "http://localhost:9999/cb"
	hash, err := bcryptHash(clientSecret)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	_, err = integPool.Exec(context.Background(),
		`INSERT INTO auth.clients (id, client_secret_hash, name) VALUES ($1,$2,$3)`,
		clientID, hash, "Disable App")
	if err != nil {
		t.Fatalf("insert client: %v", err)
	}
	_, _ = integPool.Exec(context.Background(),
		`INSERT INTO auth.client_redirect_uris (client_id, redirect_uri) VALUES ($1,$2)`,
		clientID, redirectURI)

	email := "disable-user@example.com"
	makeUser(t, email, "")
	sid := loginAs(t, email, "password123")

	// Full happy path → access token.
	_, code, verifier := guardAuthorize(t, email, "password123", clientID, redirectURI)
	tok := guardExchange(t, clientID, clientSecret, redirectURI, code, verifier)
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatalf("no access token: %v", tok)
	}
	// Sanity: userinfo accepts it.
	uiReq := httptest.NewRequest("GET", "/userinfo", nil)
	uiReq.Header.Set("Authorization", "Bearer "+access)
	uiW := httptest.NewRecorder()
	integRouter.ServeHTTP(uiW, uiReq)
	if uiW.Code != http.StatusOK {
		t.Fatalf("userinfo before disable: %d", uiW.Code)
	}

	// Admin disables the client.
	_, pw := makeUser(t, "client-admin@example.com", "admin")
	adminSid := loginAs(t, "client-admin@example.com", pw)
	dReq := httptest.NewRequest("POST", "/admin/clients/"+clientID+"/disable", nil)
	dReq.AddCookie(&http.Cookie{Name: service.SessionCookieName, Value: adminSid})
	dW := httptest.NewRecorder()
	integRouter.ServeHTTP(dW, dReq)
	if dW.Code != http.StatusOK {
		t.Fatalf("disable client: status=%d body=%s", dW.Code, dW.Body.String())
	}

	// Existing tokens invalidated (AC-5-2).
	uiW2 := httptest.NewRecorder()
	integRouter.ServeHTTP(uiW2, uiReq)
	if uiW2.Code != http.StatusUnauthorized {
		t.Fatalf("userinfo after disable: %d, want 401", uiW2.Code)
	}
	// Refresh rejected too.
	refForm := url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)},
		"client_id": {clientID}, "client_secret": {clientSecret},
	}
	refReq := httptest.NewRequest("POST", "/token", strings.NewReader(refForm.Encode()))
	refReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refW := httptest.NewRecorder()
	integRouter.ServeHTTP(refW, refReq)
	if refW.Code == http.StatusOK {
		t.Fatalf("refresh after disable: got 200, want error")
	}

	// New authorize rejected.
	challenge, _ := generatePKCE()
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
		"scope": {"openid"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	aReq := httptest.NewRequest("GET", "/authorize?"+q.Encode(), nil)
	aReq.AddCookie(&http.Cookie{Name: service.SessionCookieName, Value: sid})
	aW := httptest.NewRecorder()
	integRouter.ServeHTTP(aW, aReq)
	if aW.Code != http.StatusNotFound && aW.Code != http.StatusBadRequest && aW.Code != http.StatusUnauthorized {
		t.Fatalf("authorize after disable: %d, want rejection", aW.Code)
	}
}

// ---- AC-5-3: admin revokes sessions → re-auth required ----

func TestE2E_Admin_RevokeUserSessions(t *testing.T) {
	cleanIntegDB(t)
	uid, pw := makeUser(t, "revoked@example.com", "")
	sid := loginAs(t, "revoked@example.com", pw)

	// Session works.
	req := httptest.NewRequest("GET", "/api/sessions", nil)
	req.AddCookie(&http.Cookie{Name: service.SessionCookieName, Value: sid})
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("sessions before revoke: %d", w.Code)
	}

	_, apw := makeUser(t, "sess-admin@example.com", "admin")
	adminSid := loginAs(t, "sess-admin@example.com", apw)
	rReq := httptest.NewRequest("POST", "/admin/users/"+uid+"/logout", nil)
	rReq.AddCookie(&http.Cookie{Name: service.SessionCookieName, Value: adminSid})
	rW := httptest.NewRecorder()
	integRouter.ServeHTTP(rW, rReq)
	if rW.Code != http.StatusOK {
		t.Fatalf("admin revoke: %d %s", rW.Code, rW.Body.String())
	}

	// Old session dead → re-auth required.
	w2 := httptest.NewRecorder()
	integRouter.ServeHTTP(w2, req)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("sessions after revoke: %d, want 401", w2.Code)
	}
}

// ---- AC-5-4: TOTP step-up, recovery code, replay rejection ----

func TestE2E_MFA_StepUpReplayAndRecovery(t *testing.T) {
	cleanIntegDB(t)
	email := "mfa-user@example.com"
	uid, pw := makeUser(t, email, "")

	// Enroll: setup then verify with a computed code.
	setupReq := httptest.NewRequest("POST", "/settings/mfa/setup", nil)
	setupReq.AddCookie(&http.Cookie{Name: service.SessionCookieName, Value: loginAs(t, email, pw)})
	setupW := httptest.NewRecorder()
	integRouter.ServeHTTP(setupW, setupReq)
	if setupW.Code != http.StatusOK {
		t.Fatalf("mfa setup: %d %s", setupW.Code, setupW.Body.String())
	}
	setup := parseJSON(setupW)
	secret, _ := setup["secret"].(string)
	if secret == "" {
		t.Fatalf("no secret: %v", setup)
	}

	code := service.ComputeTOTP(secret, time.Now())
	vReq := httptest.NewRequest("POST", "/settings/mfa/verify",
		strings.NewReader(`{"code":"`+code+`"}`))
	vReq.Header.Set("Content-Type", "application/json")
	vReq.AddCookie(&http.Cookie{Name: service.SessionCookieName, Value: loginAs(t, email, pw)})
	vW := httptest.NewRecorder()
	integRouter.ServeHTTP(vW, vReq)
	if vW.Code != http.StatusOK {
		t.Fatalf("mfa verify: %d %s", vW.Code, vW.Body.String())
	}
	recovery := parseJSON(vW)["recovery_codes"].([]any)
	if len(recovery) == 0 {
		t.Fatal("no recovery codes")
	}

	// Login now requires MFA.
	loginForMFA := func() *httptest.ResponseRecorder {
		lReq := httptest.NewRequest("POST", "/login",
			strings.NewReader(`{"email":"`+email+`","password":"`+pw+`"}`))
		lReq.Header.Set("Content-Type", "application/json")
		lW := httptest.NewRecorder()
		integRouter.ServeHTTP(lW, lReq)
		return lW
	}
	lW := loginForMFA()
	body := parseJSON(lW)
	if body["mfa_required"] != true {
		t.Fatalf("login should require MFA: %v", body)
	}
	mfaToken, _ := body["mfa_token"].(string)

	// Complete with fresh TOTP.
	code2 := service.ComputeTOTP(secret, time.Now())
	cReq := httptest.NewRequest("POST", "/login/totp",
		strings.NewReader(`{"token":"`+mfaToken+`","code":"`+code2+`"}`))
	cReq.Header.Set("Content-Type", "application/json")
	cW := httptest.NewRecorder()
	integRouter.ServeHTTP(cW, cReq)
	if cW.Code != http.StatusOK {
		t.Fatalf("mfa complete: %d %s", cW.Code, cW.Body.String())
	}
	mfaSid := extractCookie(cW)
	if mfaSid == "" {
		t.Fatal("no session after MFA")
	}

	// Replay: same token+code again → rejected (token consumed + code replay).
	cW2 := httptest.NewRecorder()
	cReq2 := httptest.NewRequest("POST", "/login/totp",
		strings.NewReader(`{"token":"`+mfaToken+`","code":"`+code2+`"}`))
	cReq2.Header.Set("Content-Type", "application/json")
	integRouter.ServeHTTP(cW2, cReq2)
	if cW2.Code != http.StatusUnauthorized {
		t.Fatalf("replayed MFA: %d, want 401", cW2.Code)
	}

	// Same code replayed on a NEW step-up (AC-5-4 replay) → rejected.
	l2 := loginForMFA()
	mfaToken2, _ := parseJSON(l2)["mfa_token"].(string)
	rReq := httptest.NewRequest("POST", "/login/totp",
		strings.NewReader(`{"token":"`+mfaToken2+`","code":"`+code2+`"}`))
	rReq.Header.Set("Content-Type", "application/json")
	rW := httptest.NewRecorder()
	integRouter.ServeHTTP(rW, rReq)
	if rW.Code != http.StatusUnauthorized {
		t.Fatalf("replayed TOTP code accepted: %d", rW.Code)
	}

	// Recovery code works (fresh step-up).
	l3 := loginForMFA()
	mfaToken3, _ := parseJSON(l3)["mfa_token"].(string)
	rc, _ := recovery[0].(string)
	rcReq := httptest.NewRequest("POST", "/login/totp",
		strings.NewReader(`{"token":"`+mfaToken3+`","code":"`+rc+`"}`))
	rcReq.Header.Set("Content-Type", "application/json")
	rcW := httptest.NewRecorder()
	integRouter.ServeHTTP(rcW, rcReq)
	if rcW.Code != http.StatusOK {
		t.Fatalf("recovery code login: %d %s", rcW.Code, rcW.Body.String())
	}

	// Same recovery code single-use.
	l4 := loginForMFA()
	mfaToken4, _ := parseJSON(l4)["mfa_token"].(string)
	rcReq2 := httptest.NewRequest("POST", "/login/totp",
		strings.NewReader(`{"token":"`+mfaToken4+`","code":"`+rc+`"}`))
	rcReq2.Header.Set("Content-Type", "application/json")
	rcW2 := httptest.NewRecorder()
	integRouter.ServeHTTP(rcW2, rcReq2)
	if rcW2.Code != http.StatusUnauthorized {
		t.Fatalf("recovery code replay accepted: %d", rcW2.Code)
	}
	_ = uid
}

// ---- AC-5-5: self-service session revoke ----

func TestE2E_Sessions_SelfServiceRevoke(t *testing.T) {
	cleanIntegDB(t)
	_, pw := makeUser(t, "devices@example.com", "")
	sid1 := loginAs(t, "devices@example.com", pw)
	sid2 := loginAs(t, "devices@example.com", pw)

	list := func(sid string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/api/sessions", nil)
		req.AddCookie(&http.Cookie{Name: service.SessionCookieName, Value: sid})
		w := httptest.NewRecorder()
		integRouter.ServeHTTP(w, req)
		return w
	}
	w := list(sid1)
	if w.Code != http.StatusOK {
		t.Fatalf("list sessions: %d", w.Code)
	}
	var payload struct {
		Sessions []struct {
			ID      string `json:"id"`
			Current bool   `json:"current"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil || len(payload.Sessions) != 2 {
		t.Fatalf("expected 2 sessions: %v %s", err, w.Body.String())
	}

	// Revoke the OTHER session from sid1's perspective.
	var other string
	for _, s := range payload.Sessions {
		if !s.Current {
			other = s.ID
		}
	}
	if other == "" {
		t.Fatal("no non-current session found")
	}
	dReq := httptest.NewRequest("DELETE", "/api/sessions/"+other, nil)
	dReq.AddCookie(&http.Cookie{Name: service.SessionCookieName, Value: sid1})
	dW := httptest.NewRecorder()
	integRouter.ServeHTTP(dW, dReq)
	if dW.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", dW.Code, dW.Body.String())
	}

	// Revoked cookie dead immediately; current one alive.
	if w := list(sid2); w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session still valid: %d", w.Code)
	}
	if w := list(sid1); w.Code != http.StatusOK {
		t.Fatalf("current session died too: %d", w.Code)
	}
}

// ---- AC-5-6: RP-initiated logout ----

func signIDToken(t *testing.T, aud, sub string) string {
	t.Helper()
	key, err := service.GetActiveKey(context.Background(), integPool, testEncKey)
	if err != nil {
		t.Fatalf("active key: %v", err)
	}
	priv, err := service.ParseRSAPrivateKey(key.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	signer, err := cristalhq.NewSignerRS(cristalhq.RS256, priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	builder := cristalhq.NewBuilder(signer)
	token, err := builder.Build(&cristalhq.RegisteredClaims{
		Subject:   sub,
		Audience:  cristalhq.Audience{aud},
		ExpiresAt: cristalhq.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:  cristalhq.NewNumericDate(time.Now()),
	})
	if err != nil {
		t.Fatalf("build token: %v", err)
	}
	return token.String()
}

func TestE2E_RPLogout_ExactMatchOnly(t *testing.T) {
	cleanIntegDB(t)
	seedSigningKey(t)
	uid, pw := makeUser(t, "rp@example.com", "")

	clientID := "rp-client"
	hash, _ := bcryptHash("rp-secret-12345")
	_, _ = integPool.Exec(context.Background(),
		`INSERT INTO auth.clients (id, client_secret_hash, name, rp_logout_allowed) VALUES ($1,$2,$3,TRUE)`,
		clientID, hash, "RP Client")
	registered := "https://rp.example.com/logged-out"
	_, _ = integPool.Exec(context.Background(),
		`INSERT INTO auth.client_post_logout_uris (client_id, redirect_uri) VALUES ($1,$2)`,
		clientID, registered)

	hint := signIDToken(t, clientID, uid)

	// Registered URI → redirect there (AC-5-6).
	q := url.Values{
		"id_token_hint":            {hint},
		"post_logout_redirect_uri": {registered},
		"state":                    {"xyz"},
	}
	req := httptest.NewRequest("GET", "/logout?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: service.SessionCookieName, Value: loginAs(t, "rp@example.com", pw)})
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)
	loc := w.Header().Get("Location")
	if w.Code != http.StatusFound || !strings.HasPrefix(loc, registered) {
		t.Fatalf("rp logout: status=%d loc=%q, want redirect to %s", w.Code, loc, registered)
	}
	if !strings.Contains(loc, "state=xyz") {
		t.Fatalf("state not propagated: %s", loc)
	}

	// Unregistered URI → /login, NEVER the attacker URI (AC-5-6).
	q2 := url.Values{
		"id_token_hint":            {hint},
		"post_logout_redirect_uri": {"https://evil.example.com/phish"},
	}
	req2 := httptest.NewRequest("GET", "/logout?"+q2.Encode(), nil)
	req2.AddCookie(&http.Cookie{Name: service.SessionCookieName, Value: loginAs(t, "rp@example.com", pw)})
	w2 := httptest.NewRecorder()
	integRouter.ServeHTTP(w2, req2)
	if loc2 := w2.Header().Get("Location"); loc2 != "/login" {
		t.Fatalf("unregistered post-logout URI: loc=%q, want /login", loc2)
	}

	// No hint at all → /login even with a URI.
	q3 := url.Values{"post_logout_redirect_uri": {registered}}
	req3 := httptest.NewRequest("GET", "/logout?"+q3.Encode(), nil)
	req3.AddCookie(&http.Cookie{Name: service.SessionCookieName, Value: loginAs(t, "rp@example.com", pw)})
	w3 := httptest.NewRecorder()
	integRouter.ServeHTTP(w3, req3)
	if loc3 := w3.Header().Get("Location"); loc3 != "/login" {
		t.Fatalf("missing hint: loc=%q, want /login", loc3)
	}
}

// ---- AC-5-7: audit trail ----

func TestE2E_Audit_TrailComplete(t *testing.T) {
	cleanIntegDB(t)
	uid, pw := makeUser(t, "audited@example.com", "")
	loginAs(t, "audited@example.com", pw)
	_, apw := makeUser(t, "auditor@example.com", "admin")
	adminSid := loginAs(t, "auditor@example.com", apw)
	// Trigger an admin action.
	req := httptest.NewRequest("POST", "/admin/users/"+uid+"/force-reset", nil)
	req.AddCookie(&http.Cookie{Name: service.SessionCookieName, Value: adminSid})
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	// Query by actor + time (AC-5-7).
	var loginCount, resetCount int
	_ = integPool.QueryRow(context.Background(),
		`SELECT count(*) FROM auth.audit_log WHERE action='login' AND actor=$1`, uid).Scan(&loginCount)
	// Actor for admin actions is the admin USER id, not the session cookie.
	adminUID, _, _ := getUserByEmail("auditor@example.com")
	_ = integPool.QueryRow(context.Background(),
		`SELECT count(*) FROM auth.audit_log WHERE action='admin.user.force_reset' AND actor=$1`,
		adminUID).Scan(&resetCount)

	if loginCount == 0 {
		t.Error("no login audit rows")
	}
	if resetCount == 0 {
		t.Error("no admin.action audit rows")
	}
}

// ---- AC-5-8: consent screen only for ungranted non-standard scopes ----

func TestE2E_Consent_ScreenAndRememberedGrant(t *testing.T) {
	cleanIntegDB(t)
	seedSigningKey(t)

	clientID, clientSecret, redirectURI := "consent-app", "consent-secret-1", "http://localhost:9999/cb"
	hash, _ := bcryptHash(clientSecret)
	_, _ = integPool.Exec(context.Background(),
		`INSERT INTO auth.clients (id, client_secret_hash, name, scopes)
		 VALUES ($1,$2,$3,'{openid,profile,email,billing:read}')`,
		clientID, hash, "Consent App")
	_, _ = integPool.Exec(context.Background(),
		`INSERT INTO auth.client_redirect_uris (client_id, redirect_uri) VALUES ($1,$2)`,
		clientID, redirectURI)

	email := "consent-user@example.com"
	makeUser(t, email, "")
	sid := loginAs(t, email, "password123")

	challenge, verifier := generatePKCE()
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
		"scope": {"openid billing:read"}, "state": {"state-aaaa"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}

	// First authorize → consent screen.
	aReq := httptest.NewRequest("GET", "/authorize?"+q.Encode(), nil)
	aReq.AddCookie(&http.Cookie{Name: service.SessionCookieName, Value: sid})
	aW := httptest.NewRecorder()
	integRouter.ServeHTTP(aW, aReq)
	if aW.Code != http.StatusFound || !strings.HasPrefix(aW.Header().Get("Location"), "/consent?") {
		t.Fatalf("expected consent redirect, got %d %q", aW.Code, aW.Header().Get("Location"))
	}

	// Approve.
	cReq := httptest.NewRequest("POST", "/consent",
		strings.NewReader(url.Values{
			"q": {q.Encode()}, "redirect_uri": {redirectURI}, "state": {"state-aaaa"},
			"decision": {"allow"},
		}.Encode()))
	cReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cReq.AddCookie(&http.Cookie{Name: service.SessionCookieName, Value: sid})
	cW := httptest.NewRecorder()
	integRouter.ServeHTTP(cW, cReq)
	if cW.Code != http.StatusFound || !strings.HasPrefix(cW.Header().Get("Location"), "/authorize?") {
		t.Fatalf("consent approve: %d %q", cW.Code, cW.Header().Get("Location"))
	}

	// Back at /authorize with the remembered grant → code issued, no consent.
	aW2 := httptest.NewRecorder()
	integRouter.ServeHTTP(aW2, aReq)
	if aW2.Code != http.StatusFound && aW2.Code != http.StatusSeeOther {
		t.Fatalf("authorize after grant: %d %s", aW2.Code, aW2.Body.String())
	}
	redir, err := url.Parse(aW2.Header().Get("Location"))
	if err != nil || redir.Query().Get("code") == "" {
		t.Fatalf("no code after consent: %q", aW2.Header().Get("Location"))
	}

	// Exchange works (grant remembered, client usable).
	tok := guardExchange(t, clientID, clientSecret, redirectURI, redir.Query().Get("code"), verifier)
	if tok["access_token"] == nil {
		t.Fatalf("no token after consent: %v", tok)
	}

	// Second authorize (fresh PKCE) skips the consent screen entirely (AC-5-8).
	challenge2, _ := generatePKCE()
	q2 := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
		"scope": {"openid billing:read"}, "state": {"state-bbbb"},
		"code_challenge": {challenge2}, "code_challenge_method": {"S256"},
	}
	aReq3 := httptest.NewRequest("GET", "/authorize?"+q2.Encode(), nil)
	aReq3.AddCookie(&http.Cookie{Name: service.SessionCookieName, Value: sid})
	aW3 := httptest.NewRecorder()
	integRouter.ServeHTTP(aW3, aReq3)
	if strings.HasPrefix(aW3.Header().Get("Location"), "/consent") {
		t.Fatalf("remembered grant still showed consent: %q", aW3.Header().Get("Location"))
	}

	// Standard scopes only never hit consent (first authorize already proved
	// billing:read gates; openid alone must go straight through).
	challenge3, _ := generatePKCE()
	q3 := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
		"scope": {"openid profile email"}, "state": {"state-cccc"},
		"code_challenge": {challenge3}, "code_challenge_method": {"S256"},
	}
	aReq4 := httptest.NewRequest("GET", "/authorize?"+q3.Encode(), nil)
	aReq4.AddCookie(&http.Cookie{Name: service.SessionCookieName, Value: sid})
	aW4 := httptest.NewRecorder()
	integRouter.ServeHTTP(aW4, aReq4)
	if strings.HasPrefix(aW4.Header().Get("Location"), "/consent") {
		t.Fatalf("standard scopes hit consent: %q", aW4.Header().Get("Location"))
	}
}

// ---- AC-5-9: signed user.created webhook ----

func TestE2E_Webhook_UserCreatedSigned(t *testing.T) {
	cleanIntegDB(t)

	received := make(chan *http.Request, 1)
	var body []byte
	var sig, ts, event string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = ioReadAll(r)
		sig = r.Header.Get("X-Zeal-Signature")
		ts = r.Header.Get("X-Zeal-Timestamp")
		event = r.Header.Get("X-Zeal-Event")
		received <- r
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Register webhook directly (admin path is covered elsewhere).
	secret := "whsec_test_123"
	_, err := integPool.Exec(context.Background(),
		`INSERT INTO auth.webhooks (url, secret, events) VALUES ($1,$2,'{user.created}')`,
		srv.URL, secret)
	if err != nil {
		t.Fatalf("insert webhook: %v", err)
	}

	// Signup fires the event.
	req := httptest.NewRequest("POST", "/signup",
		strings.NewReader(`{"email":"hooked@example.com","password":"password123"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("signup: %d %s", w.Code, w.Body.String())
	}

	select {
	case <-received:
	case <-time.After(3 * time.Second):
		t.Fatal("webhook not delivered within 3s (AC-5-9)")
	}

	if event != "user.created" {
		t.Errorf("event = %q", event)
	}
	if !service.VerifySignature(secret, ts, body, sig) {
		t.Errorf("signature invalid: sig=%s ts=%s body=%s", sig, ts, body)
	}
	if !strings.Contains(string(body), "hooked@example.com") {
		t.Errorf("payload missing email: %s", body)
	}
}

// ---- AC-5-10: developer portal ----

func TestE2E_Portal_CreateClientShowsSecretOnce(t *testing.T) {
	cleanIntegDB(t)
	seedSigningKey(t)
	_, pw := makeUser(t, "dev@example.com", "")
	sid := loginAs(t, "dev@example.com", pw)

	form := url.Values{
		"name":          {"My Portal App"},
		"redirect_uris": {"https://myapp.example.com/callback"},
	}
	req := httptest.NewRequest("POST", "/portal/clients", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: service.SessionCookieName, Value: sid})
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("portal create: %d %s", w.Code, w.Body.String())
	}
	html := w.Body.String()
	if !strings.Contains(html, "client_secret") && !strings.Contains(html, "Client secret") {
		t.Fatalf("secret not shown once: %s", html)
	}

	// Pull the client_id + secret out of the rendered page (readonly inputs).
	var clientID, clientSecret string
	for _, line := range strings.Split(html, "\n") {
		if !strings.Contains(line, `readonly value="`) {
			continue
		}
		v := between(line, `value="`, `"`)
		if strings.HasPrefix(v, "app-") {
			clientID = v
		} else if v != "" {
			clientSecret = v
		}
	}
	if clientID == "" || clientSecret == "" {
		t.Fatalf("could not parse credentials from page: %s", html)
	}

	// Immediately usable at /authorize.
	challenge, _ := generatePKCE()
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID},
		"redirect_uri": {"https://myapp.example.com/callback"},
		"scope":        {"openid"}, "state": {"portal-state-1"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	aReq := httptest.NewRequest("GET", "/authorize?"+q.Encode(), nil)
	aReq.AddCookie(&http.Cookie{Name: service.SessionCookieName, Value: sid})
	aW := httptest.NewRecorder()
	integRouter.ServeHTTP(aW, aReq)
	if (aW.Code != http.StatusFound && aW.Code != http.StatusSeeOther) || aW.Header().Get("Location") == "" {
		t.Fatalf("authorize with portal client: %d %s loc=%q", aW.Code, aW.Body.String(), aW.Header().Get("Location"))
	}
	if loc := aW.Header().Get("Location"); strings.Contains(loc, "error=") {
		t.Fatalf("authorize error with portal client: %s", loc)
	}
}

func between(s, a, b string) string {
	i := strings.Index(s, a)
	if i < 0 {
		return ""
	}
	s = s[i+len(a):]
	j := strings.Index(s, b)
	if j < 0 {
		return ""
	}
	return s[:j]
}

func ioReadAll(r *http.Request) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			return buf, nil
		}
	}
}

// ---- AC-5-11: Dynamic Client Registration ----

func TestE2E_DCR_SoftwareStatementAndAllowlist(t *testing.T) {
	cleanIntegDB(t)

	// Disabled by default (opt-in).
	req := httptest.NewRequest("POST", "/register", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("DCR without secret: %d, want 403", w.Code)
	}
}

func TestE2E_DCR_EnabledFlow(t *testing.T) {
	cleanIntegDB(t)
	t.Setenv("DCR_SOFTWARE_STATEMENT_SECRET", "dcr-test-secret-32-bytes-long!!")
	t.Setenv("DCR_DEVELOPER_ALLOWLIST", "approved@example.com")

	// Rebuild DCR handler reads env at request time — env is set, handler
	// reads os.Getenv per request via Enabled()/secret at construction…
	// The router's DCRHandler was built at startup; for the test we hit the
	// registered route which captured the old secret. Force by re-reading:
	// secret is stored on the struct at construction, so this test relies on
	// the handler reading env — patch: NewDCRHandler reads at construction.
	// Workaround: the router is built in TestMain before t.Setenv. So we
	// register env BEFORE first use is impossible here. Instead verify the
	// allowlist logic directly through a freshly built handler.
	dcr := NewDCRHandler(integPool, nil)
	if !dcr.Enabled() {
		t.Fatal("DCR should be enabled with secret set")
	}

	signer, err := cristalhq.NewSignerHS(cristalhq.HS256, []byte("dcr-test-secret-32-bytes-long!!"))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	b := cristalhq.NewBuilder(signer)
	stmt, err := b.Build(&cristalhq.RegisteredClaims{
		Subject:   "approved@example.com",
		ExpiresAt: cristalhq.NewNumericDate(time.Now().Add(time.Minute)),
	})
	if err != nil {
		t.Fatalf("build stmt: %v", err)
	}

	body := `{"client_name":"Third Party","redirect_uris":["https://tp.example.com/cb"]}`
	req := httptest.NewRequest("POST", "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+stmt.String())
	w := httptest.NewRecorder()
	dcr.Register(w, req) // direct handler call (router built pre-env)
	if w.Code != http.StatusCreated {
		t.Fatalf("DCR register: %d %s", w.Code, w.Body.String())
	}
	resp := parseJSON(w)
	if resp["client_id"] == nil || resp["client_secret"] == nil {
		t.Fatalf("missing credentials: %v", resp)
	}

	// Unknown developer rejected when allowlist enforced (AC-5-11).
	badStmt, _ := b.Build(&cristalhq.RegisteredClaims{
		Subject:   "stranger@example.com",
		ExpiresAt: cristalhq.NewNumericDate(time.Now().Add(time.Minute)),
	})
	req2 := httptest.NewRequest("POST", "/register", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+badStmt.String())
	w2 := httptest.NewRecorder()
	dcr.Register(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Fatalf("unknown developer: %d, want 403", w2.Code)
	}
}

// ---- AC-5-12: role-gated admin via bearer token ----

func TestE2E_RBAC_BearerTokenRoleGate(t *testing.T) {
	cleanIntegDB(t)
	seedSigningKey(t)

	// Two clients for the two users' flows.
	for _, id := range []string{"rbac-app"} {
		hash, _ := bcryptHash("rbac-secret-12345")
		_, _ = integPool.Exec(context.Background(),
			`INSERT INTO auth.clients (id, client_secret_hash, name) VALUES ($1,$2,$3)`,
			id, hash, "RBAC App")
		_, _ = integPool.Exec(context.Background(),
			`INSERT INTO auth.client_redirect_uris (client_id, redirect_uri) VALUES ($1,$2)`,
			id, "http://localhost:9999/cb")
	}

	getToken := func(email, role string) string {
		t.Helper()
		_, pw := makeUser(t, email, role)
		_, code, verifier := guardAuthorize(t, email, pw, "rbac-app", "http://localhost:9999/cb")
		tok := guardExchange(t, "rbac-app", "rbac-secret-12345", "http://localhost:9999/cb", code, verifier)
		access, _ := tok["access_token"].(string)
		if access == "" {
			t.Fatalf("no access token for %s: %v", email, tok)
		}
		return access
	}

	adminToken := getToken("rbac-admin@example.com", "admin")
	userToken := getToken("rbac-plain@example.com", "")

	// Token carrying admin role passes the role-gated check (AC-5-12).
	req := httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("admin-role token: %d, want 200", w.Code)
	}

	// Same endpoint, token without the role → denied.
	req2 := httptest.NewRequest("GET", "/admin", nil)
	req2.Header.Set("Authorization", "Bearer "+userToken)
	w2 := httptest.NewRecorder()
	integRouter.ServeHTTP(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Fatalf("plain token: %d, want 403", w2.Code)
	}
}

// Silence unused-import guard for fmt/json used above.
var _ = fmt.Sprintf
var _ = fosite.AccessToken

// ---- 5.11: client_credentials grant ----

func TestE2E_ClientCredentials_Grant(t *testing.T) {
	cleanIntegDB(t)
	clientID, clientSecret := "svc-app", "svc-secret-12345"
	hash, _ := bcryptHash(clientSecret)
	_, err := integPool.Exec(context.Background(),
		`INSERT INTO auth.clients (id, client_secret_hash, name) VALUES ($1,$2,$3)`,
		clientID, hash, "Service App")
	if err != nil {
		t.Fatalf("insert client: %v", err)
	}

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {"openid"},
	}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("client_credentials: %d %s", w.Code, w.Body.String())
	}
	tok := parseJSON(w)
	if tok["access_token"] == nil || tok["access_token"] == "" {
		t.Fatalf("no access_token: %v", tok)
	}
}
