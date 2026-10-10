package handler

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/zeal/auth/internal/service"
)

// ProfileHandler serves the self-service surface (spec 5.7 sessions, 5.9
// profile/password/social-link management). All routes session-gated.
type ProfileHandler struct {
	pool    *pgxpool.Pool
	session *service.SessionService
	audit   *service.AuditService
}

func NewProfileHandler(pool *pgxpool.Pool, session *service.SessionService, audit *service.AuditService) *ProfileHandler {
	return &ProfileHandler{pool: pool, session: session, audit: audit}
}

// GET /api/sessions — own active sessions (spec 5.7, AC-5-5).
func (h *ProfileHandler) ListSessions(w http.ResponseWriter, r *http.Request, userID string) {
	sessions, err := h.session.ListForUser(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	// Annotate which one is the current session.
	current := service.GetSessionIDFromRequest(r)
	type s struct {
		ID        string `json:"id"`
		ClientID  string `json:"client_id"`
		ExpiresAt string `json:"expires_at"`
		Current   bool   `json:"current"`
	}
	out := make([]s, 0, len(sessions))
	for _, sess := range sessions {
		out = append(out, s{ID: sess.ID, ClientID: sess.ClientID,
			ExpiresAt: sess.ExpiresAt.UTC().Format(http.TimeFormat), Current: sess.ID == current})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

// DELETE /api/sessions/{id} — revoke one own session (spec 5.7, AC-5-5).
func (h *ProfileHandler) RevokeSession(w http.ResponseWriter, r *http.Request, userID, sessionID string) {
	sess, err := h.session.Get(r.Context(), sessionID)
	if err != nil || sess == nil || sess.UserID != userID {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session_not_found"})
		return
	}
	if err := h.session.Delete(r.Context(), sessionID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	h.audit.Log(r.Context(), userID, "session.revoked", sessionID, clientIP(r), nil)
	writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

// GET /api/profile — email + linked identities (spec 5.9).
func (h *ProfileHandler) Get(w http.ResponseWriter, r *http.Request, userID string) {
	var email string
	var verified bool
	if err := h.pool.QueryRow(r.Context(),
		`SELECT email, email_verified FROM auth.users WHERE id = $1`, userID,
	).Scan(&email, &verified); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user_not_found"})
		return
	}

	rows, _ := h.pool.Query(r.Context(),
		`SELECT provider, provider_user_id FROM auth.federated_identities WHERE user_id = $1`, userID)
	type ident struct {
		Provider string `json:"provider"`
	}
	var identities []ident
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var provider, _pid string
			if err := rows.Scan(&provider, &_pid); err == nil {
				identities = append(identities, ident{Provider: provider})
			}
		}
	}
	if identities == nil {
		identities = []ident{}
	}

	var hasPassword bool
	_ = h.pool.QueryRow(r.Context(),
		`SELECT password_hash IS NOT NULL FROM auth.users WHERE id = $1`, userID).Scan(&hasPassword)

	writeJSON(w, http.StatusOK, map[string]any{
		"email":          email,
		"email_verified": verified,
		"identities":     identities,
		"has_password":   hasPassword,
	})
}

type changePasswordRequest struct {
	CurrentPassword string
	NewPassword     string
}

// POST /api/profile/password — JSON change-password (spec 5.9).
func (h *ProfileHandler) ChangePassword(w http.ResponseWriter, r *http.Request, userID string) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	if msg, ok := h.changePassword(r, userID, changePasswordRequest{req.CurrentPassword, req.NewPassword}); !ok {
		// Map known messages to status codes.
		status := http.StatusForbidden
		switch msg {
		case "password_too_short":
			status = http.StatusBadRequest
		case "internal_error":
			status = http.StatusInternalServerError
		}
		writeJSON(w, status, map[string]string{"error": msg})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"password_changed": true, "other_sessions_revoked": true})
}

// changePassword verifies the current password, sets the new one, and revokes
// all OTHER sessions + tokens (AC-RESET-3 parity). Returns (errMsg, ok).
func (h *ProfileHandler) changePassword(r *http.Request, userID string, req changePasswordRequest) (string, bool) {
	if len(req.NewPassword) < 8 {
		return "password_too_short", false
	}

	var hash *string
	if err := h.pool.QueryRow(r.Context(),
		`SELECT password_hash FROM auth.users WHERE id = $1`, userID).Scan(&hash); err != nil || hash == nil {
		return "social_account_only", false
	}
	if bcrypt.CompareHashAndPassword([]byte(*hash), []byte(req.CurrentPassword)) != nil {
		return "invalid_credentials", false
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return "internal_error", false
	}
	if _, err := h.pool.Exec(r.Context(),
		`UPDATE auth.users SET password_hash = $1, updated_at = now() WHERE id = $2`,
		string(newHash), userID); err != nil {
		return "internal_error", false
	}

	// Revoke other sessions + tokens (AC-RESET-3).
	current := service.GetSessionIDFromRequest(r)
	sessions, _ := h.session.ListForUser(r.Context(), userID)
	for _, s := range sessions {
		if s.ID != current {
			_ = h.session.Delete(r.Context(), s.ID)
		}
	}
	_, _ = h.pool.Exec(r.Context(),
		`DELETE FROM auth.fosite_requests
		 WHERE (key LIKE 'refreshtoken:%' OR key LIKE 'accesstoken:%')
		   AND data->'session_data'->>'subject' = $1`, userID)

	h.audit.Log(r.Context(), userID, "password.changed", userID, clientIP(r), nil)
	return "", true
}

// GET /profile — HTML profile page (spec 5.9).
func (h *ProfileHandler) Page(w http.ResponseWriter, r *http.Request, userID string) {
	var email string
	var verified bool
	_ = h.pool.QueryRow(r.Context(),
		`SELECT email, email_verified FROM auth.users WHERE id = $1`, userID).
		Scan(&email, &verified)

	type sessRow struct {
		ID      string
		Short   string
		Current bool
	}
	sessions := []sessRow{}
	current := service.GetSessionIDFromRequest(r)
	if list, err := h.session.ListForUser(r.Context(), userID); err == nil {
		for _, s := range list {
			short := s.ID
			if len(short) > 8 {
				short = short[:8] + "…"
			}
			sessions = append(sessions, sessRow{ID: s.ID, Short: short, Current: s.ID == current})
		}
	}

	msg, errMsg := r.URL.Query().Get("msg"), r.URL.Query().Get("error")
	renderTemplate(w, "profile.html", map[string]any{
		"Email":         email,
		"EmailVerified": verified,
		"Sessions":      sessions,
		"Message":       msg,
		"Error":         errMsg,
	})
}

// POST /profile/password-form — HTML change-password (spec 5.9).
func (h *ProfileHandler) ChangePasswordForm(w http.ResponseWriter, r *http.Request, userID string) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/profile", http.StatusFound)
		return
	}
	req := changePasswordRequest{
		CurrentPassword: r.FormValue("current_password"),
		NewPassword:     r.FormValue("new_password"),
	}
	if msg, ok := h.changePassword(r, userID, req); !ok {
		http.Redirect(w, r, "/profile?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/profile?msg=Password+updated", http.StatusFound)
}

// POST /profile/sessions/{id}/revoke — HTML revoke (spec 5.7).
func (h *ProfileHandler) RevokeSessionForm(w http.ResponseWriter, r *http.Request, userID, sessionID string) {
	sess, err := h.session.Get(r.Context(), sessionID)
	if err != nil || sess == nil || sess.UserID != userID {
		http.Redirect(w, r, "/profile", http.StatusFound)
		return
	}
	_ = h.session.Delete(r.Context(), sessionID)
	h.audit.Log(r.Context(), userID, "session.revoked", sessionID, clientIP(r), nil)
	http.Redirect(w, r, "/profile", http.StatusFound)
}

// POST /api/profile/unlink {provider} — unlink a social identity (spec 5.9).
// Refused when it would leave the account with no way to log in.
func (h *ProfileHandler) UnlinkIdentity(w http.ResponseWriter, r *http.Request, userID string) {
	var req struct {
		Provider string `json:"provider"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Provider == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}

	var hasPassword bool
	_ = h.pool.QueryRow(r.Context(),
		`SELECT password_hash IS NOT NULL FROM auth.users WHERE id = $1`, userID).Scan(&hasPassword)
	var otherIdentities int
	_ = h.pool.QueryRow(r.Context(),
		`SELECT count(*) FROM auth.federated_identities WHERE user_id = $1 AND provider <> $2`,
		userID, req.Provider).Scan(&otherIdentities)

	if !hasPassword && otherIdentities == 0 {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "last_credential_method"})
		return
	}

	tag, err := h.pool.Exec(r.Context(),
		`DELETE FROM auth.federated_identities WHERE user_id = $1 AND provider = $2`,
		userID, req.Provider)
	if err != nil || tag.RowsAffected() == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "identity_not_linked"})
		return
	}
	h.audit.Log(r.Context(), userID, "identity.unlinked", userID, clientIP(r), map[string]any{"provider": req.Provider})
	writeJSON(w, http.StatusOK, map[string]bool{"unlinked": true})
}
