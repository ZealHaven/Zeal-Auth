package handler

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	cristalhq "github.com/cristalhq/jwt/v4"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/zeal/auth/internal/service"
)

// DCRHandler implements RFC 7591 Dynamic Client Registration (spec 5.15,
// AC-5-11). Opt-in: enabled only when DCR_SOFTWARE_STATEMENT_SECRET is set.
// Callers present a signed software-statement JWT; its sub must be on the
// DCR_DEVELOPER_ALLOWLIST (comma-separated) when that list is non-empty.
type DCRHandler struct {
	pool   *pgxpool.Pool
	audit  *service.AuditService
	secret string // HMAC secret verifying software statements
}

func NewDCRHandler(pool *pgxpool.Pool, audit *service.AuditService) *DCRHandler {
	return &DCRHandler{pool: pool, audit: audit, secret: os.Getenv("DCR_SOFTWARE_STATEMENT_SECRET")}
}

// Enabled reports whether DCR is switched on (spec 5.15 opt-in).
func (d *DCRHandler) Enabled() bool { return d.secret != "" }

// Register handles POST /register (RFC 7591).
func (d *DCRHandler) Register(w http.ResponseWriter, r *http.Request) {
	if !d.Enabled() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "registration_disabled"})
		return
	}

	developer, ok := d.verifySoftwareStatement(r.Header.Get("Authorization"))
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_software_statement"})
		return
	}
	if allow := os.Getenv("DCR_DEVELOPER_ALLOWLIST"); allow != "" && !inAllowlist(developer, allow) {
		d.audit.Log(r.Context(), developer, "dcr.rejected", "", clientIP(r), nil)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "developer_not_allowed"})
		return
	}

	var req struct {
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
		GrantTypes   []string `json:"grant_types"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
		req.ClientName == "" || len(req.RedirectURIs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata"})
		return
	}

	clientID := "dcr-" + randomSecret(8)
	secret := randomSecret(24)
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}

	var ownerID *string
	_ = d.pool.QueryRow(r.Context(),
		`SELECT id FROM auth.users WHERE email = $1`, developer).Scan(&ownerID)

	tx, err := d.pool.Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())

	if _, err := tx.Exec(r.Context(),
		`INSERT INTO auth.clients (id, client_secret_hash, name, owner_id) VALUES ($1,$2,$3,$4)`,
		clientID, string(hash), req.ClientName, ownerID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	for _, uri := range req.RedirectURIs {
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

	d.audit.Log(r.Context(), developer, "dcr.register", clientID, clientIP(r), nil)

	// RFC 7591 response.
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  clientID,
		"client_secret":              secret,
		"client_id_issued_at":        nowUnix(),
		"client_secret_expires_at":   0,
		"client_name":                req.ClientName,
		"redirect_uris":              req.RedirectURIs,
		"grant_types":                orDefault(req.GrantTypes, []string{"authorization_code", "refresh_token"}),
		"token_endpoint_auth_method": "client_secret_basic",
	})
}

// verifySoftwareStatement parses "Bearer <jwt>" signed with the DCR HMAC
// secret and returns its sub claim (developer identity).
func (d *DCRHandler) verifySoftwareStatement(authHeader string) (string, bool) {
	raw := strings.TrimPrefix(authHeader, "Bearer ")
	if raw == "" || raw == authHeader {
		return "", false
	}
	verifier, err := cristalhq.NewVerifierHS(cristalhq.HS256, []byte(d.secret))
	if err != nil {
		return "", false
	}
	token, err := cristalhq.Parse([]byte(raw), verifier)
	if err != nil {
		return "", false
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := token.DecodeClaims(&claims); err != nil || claims.Sub == "" {
		return "", false
	}
	return claims.Sub, true
}

func inAllowlist(developer, allow string) bool {
	for _, entry := range strings.Split(allow, ",") {
		if strings.TrimSpace(entry) == developer {
			return true
		}
	}
	return false
}

func orDefault(v, def []string) []string {
	if len(v) == 0 {
		return def
	}
	return v
}

func nowUnix() int64 {
	return timeNow().Unix()
}
