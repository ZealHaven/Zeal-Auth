package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestE2E_Broker_Google_Initiate_Redirect(t *testing.T) {
	cleanIntegDB(t)

	req := httptest.NewRequest("GET", "/oauth/google", nil)
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	// Should redirect to Google (or fail if no Google config)
	if w.Code != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want %d", w.Code, http.StatusTemporaryRedirect)
	}

	location := w.Header().Get("Location")
	if location == "" {
		t.Error("expected redirect Location header")
	}
}

func TestE2E_Broker_Google_Callback_BadState(t *testing.T) {
	cleanIntegDB(t)

	req := httptest.NewRequest("GET", "/oauth/google/callback?code=test-code&state=bad-state", nil)
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	if w.Code != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want %d", w.Code, http.StatusTemporaryRedirect)
	}

	location := w.Header().Get("Location")
	if !strings.Contains(location, "error=invalid_state") {
		t.Errorf("Location = %q, expected invalid_state error", location)
	}
}

func TestE2E_Broker_Google_Callback_MissingParams(t *testing.T) {
	cleanIntegDB(t)

	req := httptest.NewRequest("GET", "/oauth/google/callback", nil)
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	if w.Code != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want %d", w.Code, http.StatusTemporaryRedirect)
	}

	location := w.Header().Get("Location")
	if !strings.Contains(location, "error=missing_params") {
		t.Errorf("Location = %q, expected missing_params error", location)
	}
}

func TestE2E_Broker_GitHub_Initiate_Redirect(t *testing.T) {
	cleanIntegDB(t)

	req := httptest.NewRequest("GET", "/oauth/github", nil)
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	// Should redirect to GitHub (or fail if no GitHub config)
	if w.Code != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want %d", w.Code, http.StatusTemporaryRedirect)
	}

	location := w.Header().Get("Location")
	if location == "" {
		t.Error("expected redirect Location header")
	}
}

func TestE2E_Broker_GitHub_Callback_BadState(t *testing.T) {
	cleanIntegDB(t)

	req := httptest.NewRequest("GET", "/oauth/github/callback?code=test-code&state=bad-state", nil)
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	if w.Code != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want %d", w.Code, http.StatusTemporaryRedirect)
	}

	location := w.Header().Get("Location")
	if !strings.Contains(location, "error=invalid_state") {
		t.Errorf("Location = %q, expected invalid_state error", location)
	}
}

func TestE2E_Client_Create_SecretShownOnce(t *testing.T) {
	cleanIntegDB(t)

	// Create client
	req := httptest.NewRequest("POST", "/admin/clients", strings.NewReader(`{
		"id": "new-client",
		"secret": "new-secret-123",
		"name": "New Client",
		"redirect_uris": ["http://localhost/callback"]
	}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	integRouter.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", w.Code, http.StatusCreated)
	}

	resp := parseJSON(w)
	if resp["client_secret"] != "new-secret-123" {
		t.Errorf("client_secret = %q, want new-secret-123", resp["client_secret"])
	}

	// Verify redirect URI was stored
	var uriCount int
	_ = integPool.QueryRow(t.Context(),
		`SELECT count(*) FROM auth.client_redirect_uris WHERE client_id = 'new-client'`,
	).Scan(&uriCount)
	if uriCount != 1 {
		t.Errorf("expected 1 redirect URI, got %d", uriCount)
	}
}
