package handler

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

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
		},
	}
	oidcSess.Extra = map[string]any{
		"email":          sess.Email,
		"email_verified": sess.EmailVerified,
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
		"grant_types_supported":                         []string{"authorization_code", "refresh_token"},
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

// ---- /logout ----

func (h *OAuth2Handler) Logout(w http.ResponseWriter, r *http.Request) {
	// Delete session from Redis
	sessionID := service.GetSessionIDFromRequest(r)
	if sessionID != "" {
		_ = h.sessionSvc.Delete(r.Context(), sessionID)
	}

	service.ClearSessionCookie(w, h.config.CookieDomain)

	redirectURI := r.URL.Query().Get("post_logout_redirect_uri")
	if redirectURI == "" {
		redirectURI = "/login"
	}
	http.Redirect(w, r, redirectURI, http.StatusFound)
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
	err = h.pool.QueryRow(r.Context(),
		`SELECT email, email_verified FROM auth.users WHERE id = $1`,
		sess.UserID,
	).Scan(&email, &emailVerified)
	if err != nil {
		return nil, false
	}

	return &SSOSession{
		UserID:        sess.UserID,
		Email:         email,
		EmailVerified: emailVerified,
	}, true
}

func generateState() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
