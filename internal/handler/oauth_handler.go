package handler

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	cristalhq "github.com/cristalhq/jwt/v4"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"

	"github.com/zeal/auth/internal/service"
)

// OAuth2Handler handles OAuth2/OIDC endpoints.
type OAuth2Handler struct {
	oauth      *OAuthHandler
	pool       *pgxpool.Pool
	keySvc     *service.KeyService
	config     *FositeConfig
	sessionSvc *service.SessionService
}

func NewOAuth2Handler(oauth *OAuthHandler, pool *pgxpool.Pool, keySvc *service.KeyService, cfg *FositeConfig, sessionSvc *service.SessionService) *OAuth2Handler {
	return &OAuth2Handler{
		oauth:      oauth,
		pool:       pool,
		keySvc:     keySvc,
		config:     cfg,
		sessionSvc: sessionSvc,
	}
}

// ---- /authorize ----

func (h *OAuth2Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	req, err := h.oauth.fosite.NewAuthorizeRequest(ctx, r)
	if err != nil {
		h.oauth.fosite.WriteAuthorizeError(ctx, w, req, err)
		return
	}

	sess, hasSession := h.getSession(r)
	if !hasSession {
		returnTo := r.URL.RequestURI()
		http.Redirect(w, r, "/login?return_to="+url.QueryEscape(returnTo), http.StatusFound)
		return
	}

	// Spec 5.10 / AC-5-8: consent screen only for clients requesting scopes
	// beyond the standard set that haven't been granted before. Standard
	// scopes (own products) and remembered grants skip it.
	if !h.consentSatisfied(ctx, req, sess.UserID) {
		http.Redirect(w, r, "/consent?"+r.URL.RawQuery, http.StatusFound)
		return
	}

	// No consent screen for own products (MVP): grant everything the client
	// is allowed to request; fosite's scope strategy rejects the rest
	for _, scope := range req.GetRequestedScopes() {
		req.GrantScope(scope)
	}

	// Session is attached to the request by NewAuthorizeResponse, not NewAuthorizeRequest
	oidcSess := &openidSession{}
	oidcSess.Subject = sess.UserID
	oidcSess.Claims = &jwt.IDTokenClaims{
		Subject:     sess.UserID,
		RequestedAt: time.Now().UTC(),
		Extra: map[string]any{
			"email":          sess.Email,
			"email_verified": sess.EmailVerified,
			"role":           sess.Role,
		},
	}
	oidcSess.Extra = map[string]any{
		"email":          sess.Email,
		"email_verified": sess.EmailVerified,
		"role":           sess.Role,
	}

	resp, err := h.oauth.fosite.NewAuthorizeResponse(ctx, req, oidcSess)
	if err != nil {
		logOAuthErr("authorize response", err)
		h.oauth.fosite.WriteAuthorizeError(ctx, w, req, err)
		return
	}

	h.oauth.fosite.WriteAuthorizeResponse(ctx, w, req, resp)
}

// ---- /token ----

// logOAuthErr surfaces fosite's Debug/Hint fields — fosite's Error() hides them.
func logOAuthErr(op string, err error) {
	if rfcErr := fosite.ErrorToRFC6749Error(err); rfcErr != nil {
		log.Printf("%s error: hint=%q debug=%q", op, rfcErr.HintField, rfcErr.DebugField)
	} else {
		log.Printf("%s error: %+v", op, err)
	}
}

func (h *OAuth2Handler) Token(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	session := &openidSession{}
	accessRequest, err := h.oauth.fosite.NewAccessRequest(ctx, r, session)
	if err != nil {
		logOAuthErr("new access request", err)
		h.oauth.fosite.WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	resp, err := h.oauth.fosite.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		logOAuthErr("new access response", err)
		h.oauth.fosite.WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	h.oauth.fosite.WriteAccessResponse(ctx, w, accessRequest, resp)
}

// ---- /userinfo ----

func (h *OAuth2Handler) UserInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	session := &openidSession{}
	_, _, err := h.oauth.fosite.IntrospectToken(ctx, token, fosite.AccessToken, session)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}

	claims := map[string]any{
		"sub": session.Subject,
	}
	if session.Extra != nil {
		if email, ok := session.Extra["email"]; ok {
			claims["email"] = email
		}
		if ev, ok := session.Extra["email_verified"]; ok {
			claims["email_verified"] = ev
		}
		if name, ok := session.Extra["name"]; ok {
			claims["name"] = name
		}
		if role, ok := session.Extra["role"]; ok {
			claims["role"] = role // spec 5.16
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(claims)
}

// ---- /.well-known/openid-configuration ----

func (h *OAuth2Handler) Discovery(w http.ResponseWriter, _ *http.Request) {
	issuer := h.config.Issuer
	doc := map[string]any{
		"issuer":                                        issuer,
		"authorization_endpoint":                        issuer + "/authorize",
		"token_endpoint":                                issuer + "/token",
		"userinfo_endpoint":                             issuer + "/userinfo",
		"jwks_uri":                                      issuer + "/jwks.json",
		"revocation_endpoint":                           issuer + "/revoke",
		"introspection_endpoint":                        issuer + "/introspect",
		"response_types_supported":                      []string{"code"},
		"grant_types_supported":                         []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":                       []string{"public"},
		"id_token_signing_alg_values_supported":         []string{"RS256"},
		"scopes_supported":                              []string{"openid", "profile", "email"},
		"code_challenge_methods_supported":              []string{"S256"},
		"token_endpoint_auth_methods_supported":         []string{"client_secret_post", "client_secret_basic"},
		"introspection_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		"revocation_endpoint_auth_methods_supported":    []string{"client_secret_basic", "client_secret_post"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}

// ---- /revoke (RFC 7009) ----

func (h *OAuth2Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	err := h.oauth.fosite.NewRevocationRequest(ctx, r)
	h.oauth.fosite.WriteRevocationResponse(ctx, w, err)
}

// ---- /introspect (RFC 7662) ----

func (h *OAuth2Handler) Introspect(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := &openidSession{}
	responder, err := h.oauth.fosite.NewIntrospectionRequest(ctx, r, session)
	if err != nil {
		logOAuthErr("introspection", err)
		h.oauth.fosite.WriteIntrospectionError(ctx, w, err)
		return
	}
	h.oauth.fosite.WriteIntrospectionResponse(ctx, w, responder)
}

// ---- /jwks.json ----

func (h *OAuth2Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	keys, err := h.keySvc.GetAllActiveKeys(r.Context())
	if err != nil {
		http.Error(w, "internal_error", http.StatusInternalServerError)
		return
	}

	var jwkList []any
	for _, kp := range keys {
		pubKey, err := service.ParseRSAPublicKeyPEM(kp.PublicKeyPEM)
		if err != nil {
			continue
		}
		jwkList = append(jwkList, map[string]any{
			"kty": "RSA",
			"kid": kp.KID,
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x01}),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"keys": jwkList})
}

// ---- /logout (spec 5.8: RP-initiated logout) ----

// Logout clears the session and revokes the user's tokens. With an
// id_token_hint + post_logout_redirect_uri it performs OIDC RP-initiated
// logout: the URI must be an EXACT match on the client's registered
// post-logout URIs and that client must be rp_logout_allowed (AC-5-6).
func (h *OAuth2Handler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sessionID := service.GetSessionIDFromRequest(r)
	if sessionID != "" {
		if sess, err := h.sessionSvc.Get(ctx, sessionID); err == nil && sess != nil {
			// Revoke all tokens issued to this user — same subject delete as
			// password reset (AC-3-6: refresh token must not survive logout)
			if _, err := h.pool.Exec(ctx,
				`DELETE FROM auth.fosite_requests
				 WHERE (key LIKE 'refreshtoken:%' OR key LIKE 'accesstoken:%')
				   AND data->'session_data'->>'subject' = $1`,
				sess.UserID,
			); err != nil {
				log.Printf("logout: revoke tokens: %v", err)
				http.Error(w, "internal_error", http.StatusInternalServerError)
				return
			}
		}
		_ = h.sessionSvc.Delete(ctx, sessionID)
	}

	service.ClearSessionCookie(w, h.config.CookieDomain)

	redirectURI := r.URL.Query().Get("post_logout_redirect_uri")
	if redirectURI != "" {
		if _, ok := h.validatePostLogout(ctx, r, redirectURI); ok {
			if state := r.URL.Query().Get("state"); state != "" {
				sep := "?"
				if strings.Contains(redirectURI, "?") {
					sep = "&"
				}
				redirectURI += sep + "state=" + url.QueryEscape(state)
			}
			http.Redirect(w, r, redirectURI, http.StatusFound)
			return
		}
		// Unregistered/unallowed URI → never bounce there (AC-5-6 exact match).
	}

	http.Redirect(w, r, "/login", http.StatusFound)
}

// validatePostLogout enforces AC-5-6: id_token_hint must verify against our
// signing keys, its aud must be an rp_logout_allowed client, and the
// requested URI must exactly match a registered post-logout URI for that
// client. Returns the client id on success.
func (h *OAuth2Handler) validatePostLogout(ctx context.Context, r *http.Request, redirectURI string) (string, bool) {
	hint := r.URL.Query().Get("id_token_hint")
	if hint == "" {
		return "", false
	}

	aud, ok := h.verifyIDTokenAudience(ctx, hint)
	if !ok {
		return "", false
	}

	var allowed bool
	err := h.pool.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM auth.clients c
			WHERE c.id = $1 AND c.rp_logout_allowed
			  AND EXISTS (SELECT 1 FROM auth.client_post_logout_uris u
			              WHERE u.client_id = c.id AND u.redirect_uri = $2)
		 )`, aud, redirectURI).Scan(&allowed)
	if err != nil || !allowed {
		return "", false
	}
	return aud, true
}

// verifyIDTokenAudience parses the hint JWT, checks its signature against all
// active/retiring signing keys, and returns the aud claim (client id).
func (h *OAuth2Handler) verifyIDTokenAudience(ctx context.Context, raw string) (string, bool) {
	keys, err := h.keySvc.GetAllActiveKeys(ctx)
	if err != nil {
		return "", false
	}
	for _, kp := range keys {
		pub, err := service.ParseRSAPublicKeyPEM(kp.PublicKeyPEM)
		if err != nil {
			continue
		}
		verifier, err := cristalhq.NewVerifierRS(cristalhq.RS256, pub)
		if err != nil {
			continue
		}
		token, err := cristalhq.Parse([]byte(raw), verifier)
		if err != nil {
			continue
		}
		var claims struct {
			Aud cristalhq.Audience `json:"aud"`
			Sub string             `json:"sub"`
		}
		if err := token.DecodeClaims(&claims); err != nil {
			continue
		}
		if len(claims.Aud) > 0 && claims.Aud[0] != "" {
			return claims.Aud[0], true
		}
	}
	return "", false
}

// ---- consent (spec 5.10) ----

// standardScopes never trigger the consent screen (own-product MVP scopes).
var standardScopes = map[string]bool{"openid": true, "profile": true, "email": true}

// consentSatisfied reports whether the authorize request may proceed without
// a consent screen: only standard scopes requested, OR every requested scope
// already granted for this user+client (AC-5-8).
func (h *OAuth2Handler) consentSatisfied(ctx context.Context, req fosite.AuthorizeRequester, userID string) bool {
	clientID := req.GetClient().GetID()
	var ungranted int
	for _, scope := range req.GetRequestedScopes() {
		if standardScopes[scope] {
			continue
		}
		var ok bool
		if err := h.pool.QueryRow(ctx,
			`SELECT EXISTS (
				SELECT 1 FROM auth.scope_grants
				WHERE client_id = $1 AND user_id = $2 AND scope = $3
			 )`, clientID, userID, scope).Scan(&ok); err != nil || !ok {
			ungranted++
		}
	}
	return ungranted == 0
}

// ConsentPage renders the approval screen (GET /consent?<authorize query>).
func (h *OAuth2Handler) ConsentPage(w http.ResponseWriter, r *http.Request) {
	rawQuery := r.URL.RawQuery
	q, err := url.ParseQuery(rawQuery)
	if err != nil || q.Get("client_id") == "" || q.Get("redirect_uri") == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	var name string
	_ = h.pool.QueryRow(r.Context(),
		`SELECT name FROM auth.clients WHERE id = $1 AND status = 'active'`,
		q.Get("client_id")).Scan(&name)
	if name == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	var scopes []string
	for _, s := range strings.Fields(q.Get("scope")) {
		if !standardScopes[s] {
			scopes = append(scopes, s)
		}
	}

	sess, ok := h.getSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	renderTemplate(w, "consent.html", map[string]any{
		"ClientName":  name,
		"Scopes":      scopes,
		"Email":       sess.Email,
		"RawQuery":    rawQuery,
		"RedirectURI": q.Get("redirect_uri"),
		"State":       q.Get("state"),
	})
}

// ConsentDecision handles POST /consent — allow remembers the grant and
// returns to /authorize; deny sends the user back to the client with
// error=access_denied (AC-5-8).
func (h *OAuth2Handler) ConsentDecision(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	rawQuery := r.FormValue("q")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")

	deny := func() {
		sep := "?"
		if strings.Contains(redirectURI, "?") {
			sep = "&"
		}
		target := redirectURI + sep + "error=access_denied"
		if state != "" {
			target += "&state=" + url.QueryEscape(state)
		}
		http.Redirect(w, r, target, http.StatusFound)
	}

	if r.FormValue("decision") != "allow" || redirectURI == "" {
		deny()
		return
	}

	sess, ok := h.getSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil || q.Get("client_id") == "" {
		deny()
		return
	}
	clientID := q.Get("client_id")
	for _, scope := range strings.Fields(q.Get("scope")) {
		if standardScopes[scope] {
			continue
		}
		_, _ = h.pool.Exec(r.Context(),
			`INSERT INTO auth.scope_grants (client_id, user_id, scope) VALUES ($1,$2,$3)
			 ON CONFLICT DO NOTHING`, clientID, sess.UserID, scope)
	}

	http.Redirect(w, r, "/authorize?"+rawQuery, http.StatusFound)
}

// ---- Admin: Create Client ----

func (h *OAuth2Handler) CreateClient(w http.ResponseWriter, r *http.Request) {
	// Fail closed: no token configured → admin API disabled
	if h.config.AdminToken == "" ||
		subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Admin-Token")), []byte(h.config.AdminToken)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var req struct {
		ID           string   `json:"id"`
		Secret       string   `json:"secret"`
		Name         string   `json:"name"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}

	if req.ID == "" || req.Secret == "" || req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_required_fields"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Secret), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}

	_, err = h.pool.Exec(r.Context(),
		`INSERT INTO auth.clients (id, client_secret_hash, name) VALUES ($1, $2, $3)
		 ON CONFLICT (id) DO UPDATE SET name = $3`,
		req.ID, string(hash), req.Name,
	)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "client_id_already_exists"})
		return
	}

	for _, uri := range req.RedirectURIs {
		_, _ = h.pool.Exec(r.Context(),
			`INSERT INTO auth.client_redirect_uris (client_id, redirect_uri) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			req.ID, uri,
		)
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"client_id":     req.ID,
		"client_secret": req.Secret,
		"name":          req.Name,
	})
}

// ---- Session ----

type SSOSession struct {
	UserID        string
	Email         string
	EmailVerified bool
	Role          string // spec 5.16 RBAC claim
}

// openidSession implements fosite.Session and openid.Session for OIDC flows.
type openidSession struct {
	fosite.DefaultSession
	Claims  *jwt.IDTokenClaims `json:"claims,omitempty"`
	Headers *jwt.Headers       `json:"headers,omitempty"`
	Extra   map[string]any     `json:"extra,omitempty"`
}

func (s *openidSession) IDTokenClaims() *jwt.IDTokenClaims {
	if s.Claims == nil {
		s.Claims = &jwt.IDTokenClaims{RequestedAt: time.Now().UTC()}
	}
	return s.Claims
}

func (s *openidSession) IDTokenHeaders() *jwt.Headers {
	if s.Headers == nil {
		s.Headers = &jwt.Headers{}
	}
	return s.Headers
}

func (s *openidSession) Clone() fosite.Session {
	c := &openidSession{
		Extra: make(map[string]any, len(s.Extra)),
	}
	c.Subject = s.Subject
	c.Username = s.Username
	if s.ExpiresAt != nil {
		c.ExpiresAt = make(map[fosite.TokenType]time.Time, len(s.ExpiresAt))
		for k, v := range s.ExpiresAt {
			c.ExpiresAt[k] = v
		}
	}
	for k, v := range s.Extra {
		c.Extra[k] = v
	}
	if s.Claims != nil {
		claimsCopy := *s.Claims
		if s.Claims.Extra != nil {
			claimsCopy.Extra = make(map[string]any, len(s.Claims.Extra))
			for k, v := range s.Claims.Extra {
				claimsCopy.Extra[k] = v
			}
		}
		c.Claims = &claimsCopy
	}
	if s.Headers != nil {
		headersCopy := *s.Headers
		c.Headers = &headersCopy
	}
	return c
}

func (h *OAuth2Handler) getSession(r *http.Request) (*SSOSession, bool) {
	sessionID := service.GetSessionIDFromRequest(r)
	if sessionID == "" {
		return nil, false
	}

	sess, err := h.sessionSvc.Get(r.Context(), sessionID)
	if err != nil || sess == nil {
		return nil, false
	}

	// Look up user data from DB for the OIDC session
	var email string
	var emailVerified bool
	var role string
	err = h.pool.QueryRow(r.Context(),
		`SELECT email, email_verified, role FROM auth.users WHERE id = $1`,
		sess.UserID,
	).Scan(&email, &emailVerified, &role)
	if err != nil {
		return nil, false
	}

	return &SSOSession{
		UserID:        sess.UserID,
		Email:         email,
		EmailVerified: emailVerified,
		Role:          role,
	}, true
}

func generateState() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
