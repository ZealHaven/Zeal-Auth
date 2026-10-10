package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/zeal/auth/internal/service"
)

// AC-4-4: after rotation the old kid stays in JWKS (retiring), the new kid is
// active, and tokens signed with the old kid still verify during the overlap.
func TestE2E_KeyRotation_JWKSPublishesBothKids(t *testing.T) {
	cleanIntegDB(t)
	seedSigningKey(t) // creates active key "test-key-1"

	// Grab the current JWKS kid.
	w := makeRequest("GET", "/jwks.json", nil)
	var before struct {
		Keys []struct {
			KID string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &before); err != nil || len(before.Keys) == 0 {
		t.Fatalf("jwks before rotation: %v %s", err, w.Body.String())
	}
	oldKid := before.Keys[0].KID

	// Sign something with the old key, then rotate.
	oldKey, err := service.GetActiveKey(context.Background(), integPool, testEncKey)
	if err != nil {
		t.Fatalf("get active key: %v", err)
	}
	if _, err := service.RotateKey(context.Background(), integPool, "rotated-key-2", testEncKey); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// New kid is active.
	active, err := service.GetActiveKey(context.Background(), integPool, testEncKey)
	if err != nil {
		t.Fatalf("get active after rotation: %v", err)
	}
	if active.KID != "rotated-key-2" {
		t.Fatalf("active kid = %q, want rotated-key-2", active.KID)
	}

	// JWKS publishes both kids during the overlap (AC-OIDC-4 / AC-4-4).
	w = makeRequest("GET", "/jwks.json", nil)
	var after struct {
		Keys []struct {
			KID string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &after); err != nil {
		t.Fatalf("jwks after rotation: %v", err)
	}
	kids := map[string]bool{}
	for _, k := range after.Keys {
		kids[k.KID] = true
	}
	if !kids["rotated-key-2"] {
		t.Error("new kid missing from JWKS")
	}
	if !kids[oldKid] {
		t.Errorf("old kid %q missing from JWKS during overlap", oldKid)
	}

	// Old public key still parses — tokens signed with it verify during overlap.
	if _, err := service.ParseRSAPublicKeyPEM(oldKey.PublicKeyPEM); err != nil {
		t.Fatalf("old public key unusable during overlap: %v", err)
	}

	// RetireOldKeys with zero window retires the retiring key (loop behaviour).
	if n, err := service.RetireOldKeys(context.Background(), integPool, 0); err != nil || n < 1 {
		t.Fatalf("retire: n=%d err=%v", n, err)
	}
	if w := makeRequest("GET", "/health", nil); w.Code != http.StatusOK {
		t.Fatalf("health after rotation: %d", w.Code)
	}
}

// 4.10: sid cookie flags — Secure, HttpOnly, SameSite=Lax — enforced always;
// Secure matters behind the TLS-terminating tunnel (AC-4-7).
func TestE2E_SessionCookie_SecureFlagsInProdPath(t *testing.T) {
	cleanIntegDB(t)
	createTestUser(t, "cookie-flags@example.com", "correct-password")
	uid, _, _ := getUserByEmail("cookie-flags@example.com")
	verifyTestUser(t, uid)

	w := makeRequest("POST", "/login",
		strings.NewReader(`{"email":"cookie-flags@example.com","password":"correct-password"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("login: %d", w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name != service.SessionCookieName {
			continue
		}
		if !c.Secure {
			t.Error("sid must be Secure (4.10 / AC-4-7)")
		}
		if !c.HttpOnly {
			t.Error("sid must be HttpOnly")
		}
		if c.SameSite != http.SameSiteLaxMode {
			t.Errorf("sid SameSite = %v, want Lax", c.SameSite)
		}
		return
	}
	t.Fatal("sid cookie not set")
}
