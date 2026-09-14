package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiscovery_ValidDocument(t *testing.T) {
	h := &OAuth2Handler{
		config: &FositeConfig{
			Issuer: "https://auth.example.com",
		},
	}

	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	h.Discovery(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var doc map[string]any
	if err := json.NewDecoder(w.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if doc["issuer"] != "https://auth.example.com" {
		t.Errorf("issuer = %v, want https://auth.example.com", doc["issuer"])
	}
	if doc["authorization_endpoint"] != "https://auth.example.com/authorize" {
		t.Errorf("authorization_endpoint wrong")
	}
	if doc["token_endpoint"] != "https://auth.example.com/token" {
		t.Errorf("token_endpoint wrong")
	}
	if doc["jwks_uri"] != "https://auth.example.com/jwks.json" {
		t.Errorf("jwks_uri wrong")
	}
	if doc["response_types_supported"] == nil {
		t.Error("response_types_supported missing")
	}
	if doc["code_challenge_methods_supported"] == nil {
		t.Error("code_challenge_methods_supported missing")
	}
}

func TestDiscovery_ScopesSupported(t *testing.T) {
	h := &OAuth2Handler{config: &FositeConfig{Issuer: "https://auth.example.com"}}
	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	h.Discovery(w, req)

	var doc map[string]any
	_ = json.NewDecoder(w.Body).Decode(&doc)

	scopes, ok := doc["scopes_supported"].([]any)
	if !ok {
		t.Fatal("scopes_supported not an array")
	}
	hasOpenID := false
	for _, s := range scopes {
		if s == "openid" {
			hasOpenID = true
		}
	}
	if !hasOpenID {
		t.Error("scopes_supported should include openid")
	}
}

func TestLogout_ClearsSession(t *testing.T) {
	h := &OAuth2Handler{
		config: &FositeConfig{CookieDomain: "auth.example.com"},
	}

	req := httptest.NewRequest("GET", "/logout", nil)
	w := httptest.NewRecorder()
	h.Logout(w, req)

	cookies := w.Result().Cookies()
	var ssoCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "sid" {
			ssoCookie = c
			break
		}
	}
	if ssoCookie == nil {
		t.Fatal("sid cookie not set")
	}
	if ssoCookie.MaxAge != -1 {
		t.Errorf("MaxAge = %d, want -1", ssoCookie.MaxAge)
	}
	if ssoCookie.Value != "" {
		t.Errorf("cookie value should be empty, got %q", ssoCookie.Value)
	}
}

func TestLogout_Redirect(t *testing.T) {
	h := &OAuth2Handler{config: &FositeConfig{}}

	req := httptest.NewRequest("GET", "/logout", nil)
	w := httptest.NewRecorder()
	h.Logout(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
	}
	location := w.Header().Get("Location")
	if location != "/login" {
		t.Errorf("Location = %q, want /login", location)
	}
}

func TestLogout_PostLogoutRedirect(t *testing.T) {
	h := &OAuth2Handler{config: &FositeConfig{}}

	req := httptest.NewRequest("GET", "/logout?post_logout_redirect_uri=https://app.example.com", nil)
	w := httptest.NewRecorder()
	h.Logout(w, req)

	location := w.Header().Get("Location")
	if location != "https://app.example.com" {
		t.Errorf("Location = %q, want https://app.example.com", location)
	}
}

func TestCreateClient_MissingFields(t *testing.T) {
	h := &OAuth2Handler{}

	body := `{"id":"test"}`
	req := httptest.NewRequest("POST", "/admin/clients", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateClient(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestUserInfo_NoToken(t *testing.T) {
	h := &OAuth2Handler{}

	req := httptest.NewRequest("GET", "/userinfo", nil)
	w := httptest.NewRecorder()
	h.UserInfo(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}
