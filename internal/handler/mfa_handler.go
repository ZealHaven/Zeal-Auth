package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zeal/auth/internal/service"
)

// timeNow is injectable so TOTP tests can pin the clock.
var timeNow = time.Now

// MfaHandler implements TOTP MFA (spec 5.6, AC-5-4): enroll/verify at
// settings, login step-up, single-use recovery codes.
type MfaHandler struct {
	pool    *pgxpool.Pool
	session *service.SessionService
	audit   *service.AuditService
}

func NewMfaHandler(pool *pgxpool.Pool, session *service.SessionService, audit *service.AuditService) *MfaHandler {
	return &MfaHandler{pool: pool, session: session, audit: audit}
}

// ---- settings (session-gated; requires password confirm for enable/disable) ----

// POST /settings/mfa/setup → {secret, otpauth_uri}. Stores a NOT-yet-enabled
// secret; nothing is enforced until /verify succeeds.
func (h *MfaHandler) Setup(w http.ResponseWriter, r *http.Request, userID, email string) {
	secret, err := service.GenerateTOTPSecret()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if _, err := h.pool.Exec(r.Context(),
		`UPDATE auth.users SET totp_secret = $1, totp_enabled = FALSE, updated_at = now() WHERE id = $2`,
		secret, userID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"secret":      secret,
		"otpauth_uri": service.TOTPProvisioningURI("Zeal Auth", email, secret),
	})
}

// POST /settings/mfa/verify {code} → enable + return recovery codes (once).
func (h *MfaHandler) Verify(w http.ResponseWriter, r *http.Request, userID string) {
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}

	var secret *string
	err := h.pool.QueryRow(r.Context(),
		`SELECT totp_secret FROM auth.users WHERE id = $1`, userID).Scan(&secret)
	if err != nil || secret == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mfa_not_setup"})
		return
	}
	if !service.ValidateTOTP(*secret, req.Code, timeNow()) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_code"})
		return
	}

	codes, err := service.GenerateRecoveryCodes(8)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	// Replace any prior codes.
	_, _ = h.pool.Exec(r.Context(), `DELETE FROM auth.mfa_recovery_codes WHERE user_id = $1`, userID)
	for _, c := range codes {
		if _, err := h.pool.Exec(r.Context(),
			`INSERT INTO auth.mfa_recovery_codes (user_id, code_hash) VALUES ($1, $2)`,
			userID, service.HashToken(c)); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
			return
		}
	}
	if _, err := h.pool.Exec(r.Context(),
		`UPDATE auth.users SET totp_enabled = TRUE, updated_at = now() WHERE id = $1`, userID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	h.audit.Log(r.Context(), userID, "mfa.enabled", userID, clientIP(r), nil)
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "recovery_codes": codes})
}

// POST /settings/mfa/disable {code} — any valid TOTP or recovery code.
func (h *MfaHandler) Disable(w http.ResponseWriter, r *http.Request, userID string) {
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	if !h.consumeCode(r, userID, req.Code) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid_code"})
		return
	}
	_, _ = h.pool.Exec(r.Context(),
		`UPDATE auth.users SET totp_enabled = FALSE, totp_secret = NULL, updated_at = now() WHERE id = $1`, userID)
	_, _ = h.pool.Exec(r.Context(), `DELETE FROM auth.mfa_recovery_codes WHERE user_id = $1`, userID)
	h.audit.Log(r.Context(), userID, "mfa.disabled", userID, clientIP(r), nil)
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": false})
}

// POST /login/totp — complete the login step-up (spec 5.6, AC-5-4).
// Accepts JSON {token,code} or the HTML form (same fields); replays rejected.
func (h *MfaHandler) CompleteLogin(w http.ResponseWriter, r *http.Request, cookieDomain string) {
	var token, code string
	if isHTMLRequest(r) {
		if err := r.ParseForm(); err != nil {
			renderTemplate(w, "mfa.html", map[string]string{"Error": "Invalid form data"})
			return
		}
		token, code = r.FormValue("token"), r.FormValue("code")
	} else {
		var req struct {
			Token string `json:"token"`
			Code  string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
			return
		}
		token, code = req.Token, req.Code
	}

	failHTML := func(msg string) {
		renderTemplate(w, "mfa.html", map[string]string{"Token": token, "Error": msg})
	}

	userID := h.session.GetPendingMFA(r.Context(), token)
	if userID == "" {
		if isHTMLRequest(r) {
			failHTML("This code prompt expired. Please log in again.")
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "mfa_token_invalid"})
		return
	}
	if !h.consumeCode(r, userID, code) {
		if isHTMLRequest(r) {
			failHTML("Invalid or reused code. Try again.")
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_code"})
		return
	}
	h.session.DeletePendingMFA(r.Context(), token)

	sess, err := h.session.Create(r.Context(), userID, "")
	if err != nil {
		if isHTMLRequest(r) {
			failHTML("Something went wrong. Please try again.")
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	service.SetSessionCookie(w, sess.ID, cookieDomain)
	h.audit.Log(r.Context(), userID, "login", userID, clientIP(r), map[string]any{"mfa": true})

	if isHTMLRequest(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"message": "Login successful", "user_id": userID})
}

// consumeCode validates a TOTP code (replay-guarded) OR a recovery code
// (single-use). AC-5-4: the same TOTP code cannot be replayed.
func (h *MfaHandler) consumeCode(r *http.Request, userID, code string) bool {
	var secret *string
	if err := h.pool.QueryRow(r.Context(),
		`SELECT totp_secret FROM auth.users WHERE id = $1`, userID).Scan(&secret); err != nil || secret == nil {
		return false
	}
	if service.ValidateTOTP(*secret, code, timeNow()) {
		if h.session.TOTPCodeReplayed(r.Context(), userID, code) {
			return false
		}
		h.session.RememberTOTPCode(r.Context(), userID, code)
		return true
	}
	// Recovery code: single-use.
	tag, err := h.pool.Exec(r.Context(),
		`UPDATE auth.mfa_recovery_codes SET used_at = now()
		 WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL`,
		userID, service.HashToken(code))
	return err == nil && tag.RowsAffected() > 0
}
