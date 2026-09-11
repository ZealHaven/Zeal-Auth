package service

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
)

func cleanBrokerDB(t *testing.T) {
	t.Helper()
	_, _ = testPool.Exec(context.Background(), "DELETE FROM auth.federated_identities")
	_, _ = testPool.Exec(context.Background(), "DELETE FROM auth.users")
}

func setupBrokerService(t *testing.T, googleHandler, githubHandler http.Handler) (*BrokerService, *miniredis.Miniredis) {
	t.Helper()
	cleanBrokerDB(t)

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	userRepo := repository.NewUserRepository(testPool)
	fedRepo := repository.NewFederatedRepository(testPool)

	deps := BrokerDeps{
		Users:     userRepo,
		Federated: fedRepo,
		RDB:       rdb,
	}

	if googleHandler != nil {
		gs := httptest.NewServer(googleHandler)
		t.Cleanup(gs.Close)
		deps.Google = &oauth2.Config{
			ClientID:     "test-google-id",
			ClientSecret: "test-google-secret",
			Endpoint: oauth2.Endpoint{
				AuthURL:  gs.URL + "/auth",
				TokenURL: gs.URL + "/token",
			},
			RedirectURL: "http://localhost/callback/google",
			Scopes:      []string{"openid", "email", "profile"},
		}
		deps.GoogleUserInfoURL = gs.URL + "/userinfo"
	}
	if githubHandler != nil {
		gs := httptest.NewServer(githubHandler)
		t.Cleanup(gs.Close)
		deps.GitHub = &oauth2.Config{
			ClientID:     "test-github-id",
			ClientSecret: "test-github-secret",
			Endpoint: oauth2.Endpoint{
				AuthURL:  gs.URL + "/auth",
				TokenURL: gs.URL + "/token",
			},
			RedirectURL: "http://localhost/callback/github",
			Scopes:      []string{"user:email"},
		}
		deps.GithubUserURL = gs.URL + "/user"
		deps.GithubEmailsURL = gs.URL + "/user/emails"
	}

	svc := NewBrokerService(deps)
	return svc, mr
}

// mockGoogleHandler returns an http.Handler that simulates Google OAuth
func mockGoogleHandler(t *testing.T) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"access_token": "google-access-token",
			"token_type":   "Bearer",
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer google-access-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id":             "google-user-123",
			"email":          "alice@example.com",
			"name":           "Alice Smith",
			"verified_email": true,
		})
	})
	return mux
}

func mockGitHubHandler(t *testing.T) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"access_token": "github-access-token",
			"token_type":   "Bearer",
		})
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer github-access-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id":    45678,
			"login": "bobgh",
			"name":  "Bob GitHub",
		})
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer github-access-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]any{
			{"email": "bob@example.com", "primary": true, "verified": true},
			{"email": "bobgh@users.noreply.github.com", "primary": false, "verified": true},
		})
	})
	return mux
}

func TestBroker_Initiate_ReturnsURLWithState(t *testing.T) {
	svc, _ := setupBrokerService(t, mockGoogleHandler(t), nil)
	ctx := context.Background()

	authURL, state, err := svc.Initiate(ctx, "google", "/dashboard")
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	if state == "" {
		t.Error("state should not be empty")
	}
	if authURL == "" {
		t.Error("authURL should not be empty")
	}
	if !containsSubstring(authURL, "state="+state) {
		t.Errorf("authURL should contain state param: %s", authURL)
	}
}

func TestBroker_Initiate_StateStoredInRedis(t *testing.T) {
	svc, mr := setupBrokerService(t, mockGoogleHandler(t), nil)
	ctx := context.Background()

	_, state, err := svc.Initiate(ctx, "google", "/settings")
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}

	val, err := mr.Get("oauth:state:" + state)
	if err != nil {
		t.Fatalf("state not in Redis: %v", err)
	}
	if val != "/settings" {
		t.Errorf("state value = %q, want %q", val, "/settings")
	}
}

func TestBroker_HandleCallback_NewUser(t *testing.T) {
	svc, mr := setupBrokerService(t, mockGoogleHandler(t), nil)
	ctx := context.Background()

	// Store state
	mr.Set("oauth:state:test-state-1", "/")

	result, err := svc.HandleCallback(ctx, "google", "auth-code", "test-state-1")
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if result.User == nil {
		t.Fatal("expected user")
	}
	if result.User.Email != "alice@example.com" {
		t.Errorf("Email = %q, want %q", result.User.Email, "alice@example.com")
	}
	if !result.User.EmailVerified {
		t.Error("EmailVerified should be true (IdP-verified)")
	}
	if result.User.PasswordHash != nil {
		t.Error("PasswordHash should be nil for social user")
	}
	if result.LinkRequired {
		t.Error("LinkRequired should be false")
	}

	// Verify federated identity was linked
	fedRepo := repository.NewFederatedRepository(testPool)
	fi, err := fedRepo.FindByIdentity(ctx, "google", "google-user-123")
	if err != nil {
		t.Fatalf("FindByIdentity: %v", err)
	}
	if fi.UserID != result.User.ID {
		t.Errorf("federated UserID = %v, want %v", fi.UserID, result.User.ID)
	}
}

func TestBroker_HandleCallback_ExistingLinkedUser(t *testing.T) {
	svc, mr := setupBrokerService(t, mockGoogleHandler(t), nil)
	ctx := context.Background()

	// Create user + link identity
	userRepo := repository.NewUserRepository(testPool)
	user, _ := userRepo.Create(ctx, "alice@example.com", "")
	fedRepo := repository.NewFederatedRepository(testPool)
	_ = fedRepo.Link(ctx, user.ID, "google", "google-user-123", "alice@example.com")

	mr.Set("oauth:state:test-state-2", "/")

	result, err := svc.HandleCallback(ctx, "google", "auth-code", "test-state-2")
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if result.User.ID != user.ID {
		t.Errorf("UserID = %v, want %v", result.User.ID, user.ID)
	}
	if result.LinkRequired {
		t.Error("LinkRequired should be false")
	}
}

func TestBroker_HandleCallback_UnlinkedEmail(t *testing.T) {
	svc, mr := setupBrokerService(t, mockGoogleHandler(t), nil)
	ctx := context.Background()

	// Create user with different provider (email match, no google link)
	userRepo := repository.NewUserRepository(testPool)
	user, _ := userRepo.Create(ctx, "alice@example.com", "")
	fedRepo := repository.NewFederatedRepository(testPool)
	_ = fedRepo.Link(ctx, user.ID, "github", "gh-other", "alice@example.com")

	mr.Set("oauth:state:test-state-3", "/")

	result, err := svc.HandleCallback(ctx, "google", "auth-code", "test-state-3")
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if !result.LinkRequired {
		t.Error("LinkRequired should be true")
	}
	if result.LinkProvider != "google" {
		t.Errorf("LinkProvider = %q, want %q", result.LinkProvider, "google")
	}
	if result.LinkEmail != "alice@example.com" {
		t.Errorf("LinkEmail = %q, want %q", result.LinkEmail, "alice@example.com")
	}
}

func TestBroker_HandleCallback_BadState(t *testing.T) {
	svc, _ := setupBrokerService(t, mockGoogleHandler(t), nil)
	ctx := context.Background()

	_, err := svc.HandleCallback(ctx, "google", "auth-code", "nonexistent-state")
	if err != ErrInvalidState {
		t.Errorf("expected ErrInvalidState, got %v", err)
	}
}

func TestBroker_HandleCallback_StateSingleUse(t *testing.T) {
	svc, mr := setupBrokerService(t, mockGoogleHandler(t), nil)
	ctx := context.Background()

	mr.Set("oauth:state:test-state-once", "/")

	// First use succeeds
	_, err := svc.HandleCallback(ctx, "google", "auth-code", "test-state-once")
	if err != nil {
		t.Fatalf("first HandleCallback: %v", err)
	}

	// Second use fails (state deleted)
	_, err = svc.HandleCallback(ctx, "google", "auth-code", "test-state-once")
	if err != ErrInvalidState {
		t.Errorf("expected ErrInvalidState on reuse, got %v", err)
	}
}

func TestBroker_HandleCallback_GitHub(t *testing.T) {
	svc, mr := setupBrokerService(t, nil, mockGitHubHandler(t))
	ctx := context.Background()

	mr.Set("oauth:state:test-state-gh", "/")

	result, err := svc.HandleCallback(ctx, "github", "auth-code", "test-state-gh")
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if result.User == nil {
		t.Fatal("expected user")
	}
	if result.User.Email != "bob@example.com" {
		t.Errorf("Email = %q, want %q", result.User.Email, "bob@example.com")
	}
	if !result.User.EmailVerified {
		t.Error("EmailVerified should be true")
	}
	if result.User.PasswordHash != nil {
		t.Error("PasswordHash should be nil for social user")
	}

	// Verify federated identity
	fedRepo := repository.NewFederatedRepository(testPool)
	fi, err := fedRepo.FindByIdentity(ctx, "github", "45678")
	if err != nil {
		t.Fatalf("FindByIdentity: %v", err)
	}
	if fi.UserID != result.User.ID {
		t.Errorf("federated UserID = %v, want %v", fi.UserID, result.User.ID)
	}
}

func TestBroker_HandleCallback_SocialUserNoPassword(t *testing.T) {
	svc, mr := setupBrokerService(t, mockGoogleHandler(t), nil)
	ctx := context.Background()

	mr.Set("oauth:state:test-state-np", "/")

	result, err := svc.HandleCallback(ctx, "google", "auth-code", "test-state-np")
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if result.User.PasswordHash != nil {
		t.Error("PasswordHash should be nil for social user")
	}
}

func TestBroker_HandleCallback_EmailVerifiedTrue(t *testing.T) {
	svc, mr := setupBrokerService(t, mockGoogleHandler(t), nil)
	ctx := context.Background()

	mr.Set("oauth:state:test-state-ev", "/")

	result, err := svc.HandleCallback(ctx, "google", "auth-code", "test-state-ev")
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if !result.User.EmailVerified {
		t.Error("EmailVerified should be true (IdP-trusted)")
	}
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && contains(s, sub))
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
