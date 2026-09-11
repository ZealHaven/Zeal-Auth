package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"

	"github.com/zeal/auth/internal/repository"
	"github.com/zeal/auth/internal/service"
)

func cleanBrokerHandlerDB(t *testing.T) {
	t.Helper()
	_, _ = testPool.Exec(context.Background(), "DELETE FROM auth.federated_identities")
	_, _ = testPool.Exec(context.Background(), "DELETE FROM auth.users")
}

func setupBrokerHandlerTest(t *testing.T) (*BrokerHandler, *miniredis.Miniredis) {
	t.Helper()
	cleanBrokerHandlerDB(t)

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	// Mock Google OAuth server
	googleMux := http.NewServeMux()
	googleMux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"access_token": "google-token",
			"token_type":   "Bearer",
		})
	})
	googleMux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id":             "g-123",
			"email":          "handler@example.com",
			"name":           "Handler Test",
			"verified_email": true,
		})
	})
	gs := httptest.NewServer(googleMux)
	t.Cleanup(gs.Close)

	googleCfg := &oauth2.Config{
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:  gs.URL + "/auth",
			TokenURL: gs.URL + "/token",
		},
		RedirectURL: "http://localhost/callback",
		Scopes:      []string{"openid", "email", "profile"},
	}

	userRepo := repository.NewUserRepository(testPool)
	fedRepo := repository.NewFederatedRepository(testPool)

	brokerSvc := service.NewBrokerService(service.BrokerDeps{
		Users:             userRepo,
		Federated:         fedRepo,
		RDB:               rdb,
		Google:            googleCfg,
		GoogleUserInfoURL: gs.URL + "/userinfo",
	})

	return NewBrokerHandler(brokerSvc), mr
}

func TestGoogleInitiate_RedirectsToGoogle(t *testing.T) {
	h, _ := setupBrokerHandlerTest(t)

	req := httptest.NewRequest("GET", "/oauth/google", nil)
	w := httptest.NewRecorder()

	h.GoogleInitiate(w, req)

	if w.Code != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want %d", w.Code, http.StatusTemporaryRedirect)
	}
	location := w.Header().Get("Location")
	if location == "" {
		t.Error("expected redirect Location header")
	}
}

func TestGoogleCallback_Success(t *testing.T) {
	h, mr := setupBrokerHandlerTest(t)

	mr.Set("oauth:state:good-state", "/")

	req := httptest.NewRequest("GET", "/oauth/google/callback?code=test-code&state=good-state", nil)
	w := httptest.NewRecorder()

	h.GoogleCallback(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["message"] != "Login successful" {
		t.Errorf("message = %q", resp["message"])
	}
}

func TestGoogleCallback_BadState(t *testing.T) {
	h, _ := setupBrokerHandlerTest(t)

	req := httptest.NewRequest("GET", "/oauth/google/callback?code=test-code&state=bad-state", nil)
	w := httptest.NewRecorder()

	h.GoogleCallback(w, req)

	if w.Code != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want %d", w.Code, http.StatusTemporaryRedirect)
	}
	location := w.Header().Get("Location")
	if location != "/login?error=invalid_state" {
		t.Errorf("Location = %q, want /login?error=invalid_state", location)
	}
}

func TestGoogleCallback_MissingParams(t *testing.T) {
	h, _ := setupBrokerHandlerTest(t)

	req := httptest.NewRequest("GET", "/oauth/google/callback", nil)
	w := httptest.NewRecorder()

	h.GoogleCallback(w, req)

	if w.Code != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want %d", w.Code, http.StatusTemporaryRedirect)
	}
	location := w.Header().Get("Location")
	if location != "/login?error=missing_params" {
		t.Errorf("Location = %q, want /login?error=missing_params", location)
	}
}
