package service

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSetSessionCookie_NameDomain(t *testing.T) {
	w := httptest.NewRecorder()
	SetSessionCookie(w, "test-session-id", "auth.example.com")

	cookies := w.Result().Cookies()
	var sessCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == SessionCookieName {
			sessCookie = c
			break
		}
	}
	if sessCookie == nil {
		t.Fatal("session cookie not set")
	}
	if sessCookie.Value != "test-session-id" {
		t.Errorf("Value = %q, want test-session-id", sessCookie.Value)
	}
	if sessCookie.Domain != "auth.example.com" {
		t.Errorf("Domain = %q, want auth.example.com", sessCookie.Domain)
	}
	if sessCookie.Path != "/" {
		t.Errorf("Path = %q, want /", sessCookie.Path)
	}
}

func TestSetSessionCookie_HttpOnlySecureSameSite(t *testing.T) {
	w := httptest.NewRecorder()
	SetSessionCookie(w, "test-id", "auth.example.com")

	cookies := w.Result().Cookies()
	var sessCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == SessionCookieName {
			sessCookie = c
			break
		}
	}
	if sessCookie == nil {
		t.Fatal("session cookie not set")
	}
	if !sessCookie.HttpOnly {
		t.Error("HttpOnly should be true")
	}
	if !sessCookie.Secure {
		t.Error("Secure should be true")
	}
	if sessCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", sessCookie.SameSite)
	}
}

func TestClearSessionCookie_MaxAgeNeg1(t *testing.T) {
	w := httptest.NewRecorder()
	ClearSessionCookie(w, "auth.example.com")

	cookies := w.Result().Cookies()
	var sessCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == SessionCookieName {
			sessCookie = c
			break
		}
	}
	if sessCookie == nil {
		t.Fatal("clear cookie not set")
	}
	if sessCookie.MaxAge != -1 {
		t.Errorf("MaxAge = %d, want -1", sessCookie.MaxAge)
	}
	if sessCookie.Value != "" {
		t.Errorf("Value should be empty, got %q", sessCookie.Value)
	}
}

func TestGetSessionIDFromRequest_Present(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "my-session-id"})

	got := GetSessionIDFromRequest(req)
	if got != "my-session-id" {
		t.Errorf("got %q, want my-session-id", got)
	}
}

func TestGetSessionIDFromRequest_Missing(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)

	got := GetSessionIDFromRequest(req)
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}
