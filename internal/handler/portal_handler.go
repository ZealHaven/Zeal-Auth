package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zeal/auth/internal/service"
)

// PortalHandler is the developer self-service portal (spec 5.14, AC-5-10):
// developers register and manage their own clients without the raw admin API.
// All routes session-gated.
type PortalHandler struct {
	pool  *pgxpool.Pool
	audit *service.AuditService
}

func NewPortalHandler(pool *pgxpool.Pool, audit *service.AuditService) *PortalHandler {
	return &PortalHandler{pool: pool, audit: audit}
}

// GET /portal — HTML dashboard: the developer's clients + usage counts.
func (h *PortalHandler) Page(w http.ResponseWriter, r *http.Request, userID string) {
	type clientRow struct {
		ID           string
		Name         string
		Status       string
		RedirectURIs []string
		TokenCount   int
	}
	clients := []clientRow{}
	rows, err := h.pool.Query(r.Context(),
		`SELECT c.id, c.name, c.status,
		        COALESCE(array_agg(u.redirect_uri) FILTER (WHERE u.id IS NOT NULL), '{}'),
		        (SELECT count(*) FROM auth.fosite_requests f
		          WHERE f.key LIKE 'accesstoken:%' AND f.data->'client'->>'id' = c.id)
		 FROM auth.clients c
		 LEFT JOIN auth.client_redirect_uris u ON u.client_id = c.id
		 WHERE c.owner_id = $1
		 GROUP BY c.id, c.name, c.created_at
		 ORDER BY c.created_at DESC LIMIT 100`, userID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var cr clientRow
			if err := rows.Scan(&cr.ID, &cr.Name, &cr.Status, &cr.RedirectURIs, &cr.TokenCount); err == nil {
				clients = append(clients, cr)
			}
		}
	}
	renderTemplate(w, "portal.html", map[string]any{"Clients": clients})
}

// CreateClient handles POST /portal/clients (form or JSON). Secret is shown
// once (AC-5-10) and the client is immediately usable at /authorize.
func (h *PortalHandler) CreateClient(w http.ResponseWriter, r *http.Request, userID string) {
	var name, urisRaw string
	if isHTMLRequest(r) {
		if err := r.ParseForm(); err != nil {
			http.Redirect(w, r, "/portal", http.StatusFound)
			return
		}
		name, urisRaw = r.FormValue("name"), r.FormValue("redirect_uris")
	} else {
		var req struct {
			Name         string   `json:"name"`
			RedirectURIs []string `json:"redirect_uris"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		name = req.Name
		urisRaw = strings.Join(req.RedirectURIs, "\n")
	}

	name = strings.TrimSpace(name)
	uris := splitNonEmpty(urisRaw)
	if name == "" || len(uris) == 0 {
		msg := "name and at least one redirect URI required"
		if isHTMLRequest(r) {
			renderTemplate(w, "portal.html", map[string]any{"Error": msg, "Clients": []any{}})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	clientID := "app-" + randomSecret(8)
	secret := randomSecret(24)
	hash, err := bcryptHash(secret)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())

	if _, err := tx.Exec(r.Context(),
		`INSERT INTO auth.clients (id, client_secret_hash, name, owner_id) VALUES ($1,$2,$3,$4)`,
		clientID, hash, name, userID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	for _, uri := range uris {
		if _, err := tx.Exec(r.Context(),
			`INSERT INTO auth.client_redirect_uris (client_id, redirect_uri) VALUES ($1,$2)`,
			clientID, uri); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
			return
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}

	h.audit.Log(r.Context(), userID, "client.create", clientID, clientIP(r), map[string]any{"via": "portal"})

	if isHTMLRequest(r) {
		renderTemplate(w, "portal-secret.html", map[string]any{
			"ClientID":     clientID,
			"ClientSecret": secret,
			"Name":         name,
		})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id": clientID, "client_secret": secret, "name": name,
	})
}

// POST /portal/clients/{id}/rotate — rotate the secret, shown once (5.14).
// Only the client owner may rotate.
func (h *PortalHandler) RotateSecret(w http.ResponseWriter, r *http.Request, userID, clientID string) {
	var owner *string
	if err := h.pool.QueryRow(r.Context(),
		`SELECT owner_id FROM auth.clients WHERE id = $1`, clientID).Scan(&owner); err != nil || owner == nil || *owner != userID {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "client_not_found"})
		return
	}

	secret := randomSecret(24)
	hash, err := bcryptHash(secret)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if _, err := h.pool.Exec(r.Context(),
		`UPDATE auth.clients SET client_secret_hash = $1 WHERE id = $2`, hash, clientID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	h.audit.Log(r.Context(), userID, "client.secret_rotate", clientID, clientIP(r), map[string]any{"via": "portal"})

	if isHTMLRequest(r) {
		renderTemplate(w, "portal-secret.html", map[string]any{
			"ClientID": clientID, "ClientSecret": secret, "Name": "(rotated)",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"client_id": clientID, "client_secret": secret})
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
