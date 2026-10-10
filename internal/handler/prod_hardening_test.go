package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// AC-4-3: 6 failed logins in 10 min → account/IP throttled (429);
// legitimate login works again after the window (covered by limiter TTL).
func TestE2E_RateLimit_6FailedLoginsLocked(t *testing.T) {
	cleanIntegDB(t)
	createTestUser(t, "rl-user@example.com", "correct-password")

	for i := 0; i < loginLimit; i++ {
		body := `{"email":"rl-user@example.com","password":"wrong-password"}`
		w := makeRequest("POST", "/login", strings.NewReader(body))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i+1, w.Code)
		}
	}

	// Next attempt — even with the CORRECT password — must be 429.
	body := `{"email":"rl-user@example.com","password":"correct-password"}`
	w := makeRequest("POST", "/login", strings.NewReader(body))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("locked login: status = %d, want 429", w.Code)
	}
	if ra := w.Header().Get("Retry-After"); ra == "" {
		t.Error("Retry-After header missing on 429")
	}

	// Form path uses the same limiter.
	req := httptest.NewRequest("POST", "/login-form", strings.NewReader("email=rl-user%40example.com&password=correct-password"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	fw := httptest.NewRecorder()
	integRouter.ServeHTTP(fw, req)
	if fw.Code != http.StatusTooManyRequests {
		t.Fatalf("form login when locked: status = %d, want 429", fw.Code)
	}
}

// Successful login clears the ACCOUNT counter so past failures don't linger
// (the per-IP counter is independent — different XFF per phase below).
func TestE2E_RateLimit_SuccessResetsCounter(t *testing.T) {
	cleanIntegDB(t)
	createTestUser(t, "rl-ok@example.com", "correct-password")
	// login requires a verified email (403 otherwise) — rate limiter fires first,
	// but the success leg needs verification.
	uid, _, _ := getUserByEmail("rl-ok@example.com")
	verifyTestUser(t, uid)

	login := func(password, ip string) int {
		req := httptest.NewRequest("POST", "/login",
			strings.NewReader(`{"email":"rl-ok@example.com","password":"`+password+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", ip)
		w := httptest.NewRecorder()
		integRouter.ServeHTTP(w, req)
		return w.Code
	}

	// 3 failures from IP-A (under the limit), then success → account reset.
	for i := 0; i < 3; i++ {
		if code := login("wrong", "10.1.1.1"); code != http.StatusUnauthorized {
			t.Fatalf("failure %d: status = %d", i+1, code)
		}
	}
	if code := login("correct-password", "10.1.1.1"); code != http.StatusOK {
		t.Fatalf("login: status = %d, want 200", code)
	}

	// Fresh IP + cleared account counter: 5 more failures stay under limit.
	for i := 0; i < 5; i++ {
		if code := login("wrong", "10.2.2.2"); code == http.StatusTooManyRequests {
			t.Fatalf("failure %d after reset: got 429, account counter was not cleared", i+1)
		}
	}
}

// Spec 4.9: middleware baseline — security headers on every response.
func TestE2E_Middleware_SecurityHeaders(t *testing.T) {
	w := makeRequest("GET", "/login", nil)
	h := w.Header()
	if h.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing X-Content-Type-Options: nosniff")
	}
	if h.Get("X-Frame-Options") != "DENY" {
		t.Error("missing X-Frame-Options: DENY")
	}
	if h.Get("Referrer-Policy") == "" {
		t.Error("missing Referrer-Policy")
	}
	if h.Get("Strict-Transport-Security") != "" {
		t.Error("HSTS must be off when HSTS dep flag is false")
	}
}

// Spec 4.9: panic recovery returns 500 instead of killing the connection.
func TestE2E_Middleware_PanicRecovery(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /boom", func(http.ResponseWriter, *http.Request) { panic("boom") })
	h := withMiddleware(mux, false)

	req := httptest.NewRequest("GET", "/boom", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

// Spec 4.3: X-Forwarded-Proto is captured for downstream scheme decisions.
func TestE2E_Middleware_TrustForwardedProto(t *testing.T) {
	var got string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /p", func(_ http.ResponseWriter, r *http.Request) {
		got = ForwardedProto(r)
	})
	h := withMiddleware(mux, false)

	req := httptest.NewRequest("GET", "/p", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got != "https" {
		t.Fatalf("ForwardedProto = %q, want https", got)
	}

	req = httptest.NewRequest("GET", "/p", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got != "http" {
		t.Fatalf("ForwardedProto = %q, want http", got)
	}
}
