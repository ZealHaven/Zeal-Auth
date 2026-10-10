package handler

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/zeal/auth/internal/service"
)

// AdminHandler serves the /admin/* dashboard API (spec 5.1–5.4).
// Every route is wrapped in requireAdmin at registration (handler.go).
type AdminHandler struct {
	pool    *pgxpool.Pool
	session *service.SessionService
	audit   *service.AuditService
}

func NewAdminHandler(pool *pgxpool.Pool, session *service.SessionService, audit *service.AuditService) *AdminHandler {
	return &AdminHandler{pool: pool, session: session, audit: audit}
}

func adminActor(r *http.Request) string {
	if uid := AdminUserID(r); uid != "" {
		return uid
	}
	return "admin-token"
}

// ---- 5.1 dashboard ----

// GET /admin — landing. Confirms admin can see the dashboard (AC-5-1).
func (h *AdminHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "area": "admin"})
}

// ---- 5.2 users admin ----

func (h *AdminHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, email, email_verified, role, disabled_at, created_at
		 FROM auth.users
		 WHERE ($1 = '' OR email ILIKE '%' || $1 || '%')
		 ORDER BY created_at DESC LIMIT 200`, q)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer rows.Close()

	type u struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Role          string `json:"role"`
		Disabled      bool   `json:"disabled"`
		CreatedAt     string `json:"created_at"`
	}
	var out []u
	for rows.Next() {
		var id, email, role string
		var verified bool
		var disabledAt *string
		var createdAt string
		if err := rows.Scan(&id, &email, &verified, &role, &disabledAt, &createdAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
			return
		}
		out = append(out, u{ID: id, Email: email, EmailVerified: verified, Role: role,
			Disabled: disabledAt != nil, CreatedAt: createdAt})
	}
	if out == nil {
		out = []u{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

// POST /admin/users/{id}/verify — manually verify email (5.2).
func (h *AdminHandler) VerifyUser(w http.ResponseWriter, r *http.Request, userID string) {
	tag, err := h.pool.Exec(r.Context(),
		`UPDATE auth.users SET email_verified = TRUE, updated_at = now() WHERE id = $1`, userID)
	if err != nil || tag.RowsAffected() == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user_not_found"})
		return
	}
	h.audit.Log(r.Context(), adminActor(r), "admin.user.verify", userID, clientIP(r), nil)
	writeJSON(w, http.StatusOK, map[string]bool{"email_verified": true})
}

// POST /admin/users/{id}/disable — disable account (5.2).
func (h *AdminHandler) DisableUser(w http.ResponseWriter, r *http.Request, userID string) {
	tag, err := h.pool.Exec(r.Context(),
		`UPDATE auth.users SET disabled_at = now(), updated_at = now() WHERE id = $1 AND disabled_at IS NULL`, userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if tag.RowsAffected() == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user_not_found_or_already_disabled"})
		return
	}
	// Remote logout: kill all sessions + tokens (5.4 primitive).
	_ = h.session.DeleteAllForUser(r.Context(), userID)
	_, _ = h.pool.Exec(r.Context(),
		`DELETE FROM auth.fosite_requests
		 WHERE (key LIKE 'refreshtoken:%' OR key LIKE 'accesstoken:%')
		   AND data->'session_data'->>'subject' = $1`, userID)
	h.audit.Log(r.Context(), adminActor(r), "admin.user.disable", userID, clientIP(r), nil)
	writeJSON(w, http.StatusOK, map[string]bool{"disabled": true})
}

// POST /admin/users/{id}/force-reset — flag account for password reset (5.2).
// Revokes sessions/tokens so the user must reset on next login.
func (h *AdminHandler) ForcePasswordReset(w http.ResponseWriter, r *http.Request, userID string) {
	_ = h.session.DeleteAllForUser(r.Context(), userID)
	_, _ = h.pool.Exec(r.Context(),
		`DELETE FROM auth.fosite_requests
		 WHERE (key LIKE 'refreshtoken:%' OR key LIKE 'accesstoken:%')
		   AND data->'session_data'->>'subject' = $1`, userID)
	h.audit.Log(r.Context(), adminActor(r), "admin.user.force_reset", userID, clientIP(r), nil)
	writeJSON(w, http.StatusOK, map[string]bool{"sessions_revoked": true})
}

// ---- 5.3 clients admin ----

func (h *AdminHandler) ListClients(w http.ResponseWriter, r *http.Request) {
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, name, status, created_at FROM auth.clients ORDER BY created_at DESC LIMIT 200`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer rows.Close()
	type c struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Status    string `json:"status"`
		CreatedAt string `json:"created_at"`
	}
	var out []c
	for rows.Next() {
		var id, name, status, createdAt string
		if err := rows.Scan(&id, &name, &status, &createdAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
			return
		}
		out = append(out, c{ID: id, Name: name, Status: status, CreatedAt: createdAt})
	}
	if out == nil {
		out = []c{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": out})
}

// POST /admin/clients/{id}/disable — disable client + invalidate its tokens
// (spec 5.3, AC-5-2 / AC-CLIENT-3).
func (h *AdminHandler) DisableClient(w http.ResponseWriter, r *http.Request, clientID string) {
	tag, err := h.pool.Exec(r.Context(),
		`UPDATE auth.clients SET status = 'disabled' WHERE id = $1`, clientID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if tag.RowsAffected() == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "client_not_found"})
		return
	}
	// Invalidate existing tokens issued to this client (AC-5-2). Stored
	// fosite requests carry client.id; delete access + refresh rows.
	if _, err := h.pool.Exec(r.Context(),
		`DELETE FROM auth.fosite_requests
		 WHERE (key LIKE 'accesstoken:%' OR key LIKE 'refreshtoken:%')
		   AND data->'client'->>'id' = $1`, clientID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	h.audit.Log(r.Context(), adminActor(r), "admin.client.disable", clientID, clientIP(r), nil)
	writeJSON(w, http.StatusOK, map[string]bool{"disabled": true, "tokens_invalidated": true})
}

// ---- 5.4 sessions admin ----

// GET /admin/users/{id}/sessions — list active sessions (5.4, AC-5-3).
func (h *AdminHandler) ListUserSessions(w http.ResponseWriter, r *http.Request, userID string) {
	sessions, err := h.session.ListForUser(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

// POST /admin/users/{id}/logout — revoke all sessions + tokens (5.4, AC-5-3).
func (h *AdminHandler) RevokeUserSessions(w http.ResponseWriter, r *http.Request, userID string) {
	if err := h.session.DeleteAllForUser(r.Context(), userID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	_, _ = h.pool.Exec(r.Context(),
		`DELETE FROM auth.fosite_requests
		 WHERE (key LIKE 'refreshtoken:%' OR key LIKE 'accesstoken:%')
		   AND data->'session_data'->>'subject' = $1`, userID)
	h.audit.Log(r.Context(), adminActor(r), "admin.session.revoke_all", userID, clientIP(r), nil)
	writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

// ---- 5.13 webhooks admin ----

// GET /admin/webhooks — list registered webhooks (secret masked).
func (h *AdminHandler) ListWebhooks(w http.ResponseWriter, r *http.Request) {
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, url, events, status, created_at FROM auth.webhooks ORDER BY created_at DESC LIMIT 200`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer rows.Close()
	type hook struct {
		ID        string   `json:"id"`
		URL       string   `json:"url"`
		Events    []string `json:"events"`
		Status    string   `json:"status"`
		CreatedAt string   `json:"created_at"`
	}
	var out []hook
	for rows.Next() {
		var hh hook
		if err := rows.Scan(&hh.ID, &hh.URL, &hh.Events, &hh.Status, &hh.CreatedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
			return
		}
		out = append(out, hh)
	}
	if out == nil {
		out = []hook{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"webhooks": out})
}

// POST /admin/webhooks {url, events[]} — register a webhook (5.13). Secret is
// generated and returned ONCE; receivers verify X-Zeal-Signature.
func (h *AdminHandler) CreateWebhook(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL    string   `json:"url"`
		Events []string `json:"events"`
	}
	if err := decodeJSON(r, &req); err != nil || req.URL == "" || len(req.Events) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	secret := randomSecret(32)
	var id string
	err := h.pool.QueryRow(r.Context(),
		`INSERT INTO auth.webhooks (url, secret, events) VALUES ($1,$2,$3) RETURNING id`,
		req.URL, secret, req.Events).Scan(&id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	h.audit.Log(r.Context(), adminActor(r), "admin.webhook.create", id, clientIP(r), map[string]any{"url": req.URL})
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": id, "url": req.URL, "events": req.Events, "secret": secret,
	})
}

// POST /admin/webhooks/{id}/disable — disable a webhook (5.13).
func (h *AdminHandler) DisableWebhook(w http.ResponseWriter, r *http.Request, id string) {
	tag, err := h.pool.Exec(r.Context(),
		`UPDATE auth.webhooks SET status = 'disabled' WHERE id = $1`, id)
	if err != nil || tag.RowsAffected() == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "webhook_not_found"})
		return
	}
	h.audit.Log(r.Context(), adminActor(r), "admin.webhook.disable", id, clientIP(r), nil)
	writeJSON(w, http.StatusOK, map[string]bool{"disabled": true})
}

// ---- helpers ----

// bcryptHash is exported for reuse by the developer portal (5.14).
func bcryptHash(secret string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	return string(b), err
}

// randomSecret returns a hex secret shown once (client secrets, 5.14).
func randomSecret(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// decodeJSON is a tiny helper shared by admin/portal handlers.
func decodeJSON(r *http.Request, dst any) error {
	return json.NewDecoder(r.Body).Decode(dst)
}
