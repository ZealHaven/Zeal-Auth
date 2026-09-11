package storage

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ory/fosite"
)

var testPool *pgxpool.Pool

func testDBURL() string {
	if url := os.Getenv("DATABASE_URL"); url != "" {
		return url
	}
	return "postgres://auth:auth@localhost:5435/auth?sslmode=disable"
}

func TestMain(m *testing.M) {
	ctx := context.Background()
	var err error
	testPool, err = pgxpool.New(ctx, testDBURL())
	if err != nil {
		panic("connect pool: " + err.Error())
	}

	_, _ = testPool.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS auth")

	// Check if migration 1 already ran (table exists)
	var exists bool
	_ = testPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema='auth' AND table_name='users')`).Scan(&exists)
	if !exists {
		out, _ := os.ReadFile("../../migrations/000001_init.up.sql")
		if out != nil {
			if _, err = testPool.Exec(ctx, string(out)); err != nil {
				panic("run migration 000001: " + err.Error())
			}
		}
	}
	// Check if migration 2 already ran
	_ = testPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema='auth' AND table_name='fosite_requests')`).Scan(&exists)
	if !exists {
		out, _ := os.ReadFile("../../migrations/000002_oauth2_storage.up.sql")
		if out != nil {
			if _, err = testPool.Exec(ctx, string(out)); err != nil {
				panic("run migration 000002: " + err.Error())
			}
		}
	}

	code := m.Run()

	testPool.Close()
	os.Exit(code)
}

func newTestClient(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	id := "test-client-" + uuid.New().String()[:8]
	_, err := testPool.Exec(ctx,
		`INSERT INTO auth.clients (id, client_secret_hash, name) VALUES ($1, $2, $3)`,
		id, "hashed-secret", "Test Client",
	)
	if err != nil {
		t.Fatalf("insert test client: %v", err)
	}
	_, _ = testPool.Exec(ctx,
		`INSERT INTO auth.client_redirect_uris (client_id, redirect_uri) VALUES ($1, $2)`,
		id, "http://localhost:3000/callback",
	)
	return id
}

func TestFositeStorage_GetClient(t *testing.T) {
	ctx := context.Background()
	store := NewFositeStorage(testPool)

	clientID := newTestClient(t)

	client, err := store.GetClient(ctx, clientID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if client.GetID() != clientID {
		t.Errorf("GetID() = %q, want %q", client.GetID(), clientID)
	}
	if len(client.GetRedirectURIs()) != 1 {
		t.Errorf("len(RedirectURIs) = %d, want 1", len(client.GetRedirectURIs()))
	}
}

func TestFositeStorage_GetClient_NotFound(t *testing.T) {
	ctx := context.Background()
	store := NewFositeStorage(testPool)

	_, err := store.GetClient(ctx, "nonexistent")
	if err != fosite.ErrNotFound {
		t.Errorf("expected fosite.ErrNotFound, got %v", err)
	}
}

func TestFositeStorage_GetClient_Disabled(t *testing.T) {
	ctx := context.Background()
	store := NewFositeStorage(testPool)

	id := "disabled-client-" + uuid.New().String()[:8]
	_, _ = testPool.Exec(ctx,
		`INSERT INTO auth.clients (id, client_secret_hash, name, status)
		 VALUES ($1, $2, $3, 'disabled')`,
		id, "hash", "Disabled",
	)

	_, err := store.GetClient(ctx, id)
	if err != fosite.ErrNotFound {
		t.Errorf("expected fosite.ErrNotFound for disabled client, got %v", err)
	}
}

func TestFositeStorage_AuthCode_Session(t *testing.T) {
	ctx := context.Background()
	store := NewFositeStorage(testPool)

	code := "test-auth-code-" + uuid.New().String()
	req := &fosite.Request{
		ID:          uuid.New().String(),
		RequestedAt: time.Now().UTC(),
		Client:      &fosite.DefaultClient{ID: "c1"},
		Form:        map[string][]string{"scope": {"openid"}},
		Session:     &fosite.DefaultSession{Subject: "user-1"},
	}

	err := store.CreateAuthorizeCodeSession(ctx, code, req)
	if err != nil {
		t.Fatalf("CreateAuthorizeCodeSession: %v", err)
	}

	session := &fosite.DefaultSession{}
	got, err := store.GetAuthorizeCodeSession(ctx, code, session)
	if err != nil {
		t.Fatalf("GetAuthorizeCodeSession: %v", err)
	}
	if got.GetID() != req.ID {
		t.Errorf("GetID() = %q, want %q", got.GetID(), req.ID)
	}
	if session.Subject != "user-1" {
		t.Errorf("Subject = %q, want %q", session.Subject, "user-1")
	}
}

func TestFositeStorage_AuthCode_Delete(t *testing.T) {
	ctx := context.Background()
	store := NewFositeStorage(testPool)

	code := "del-auth-code-" + uuid.New().String()
	req := &fosite.Request{
		ID:          uuid.New().String(),
		RequestedAt: time.Now().UTC(),
		Client:      &fosite.DefaultClient{ID: "c1"},
	}
	_ = store.CreateAuthorizeCodeSession(ctx, code, req)

	err := store.InvalidateAuthorizeCodeSession(ctx, code)
	if err != nil {
		t.Fatalf("InvalidateAuthorizeCodeSession: %v", err)
	}

	_, err = store.GetAuthorizeCodeSession(ctx, code, nil)
	if err == nil {
		t.Error("expected error after invalidation")
	}
}

func TestFositeStorage_AccessToken_CRUD(t *testing.T) {
	ctx := context.Background()
	store := NewFositeStorage(testPool)

	sig := "at-sig-" + uuid.New().String()
	req := &fosite.Request{
		ID:          uuid.New().String(),
		RequestedAt: time.Now().UTC(),
		Client:      &fosite.DefaultClient{ID: "c1"},
		Session:     &fosite.DefaultSession{Subject: "user-1"},
	}

	err := store.CreateAccessTokenSession(ctx, sig, req)
	if err != nil {
		t.Fatalf("CreateAccessTokenSession: %v", err)
	}

	session := &fosite.DefaultSession{}
	got, err := store.GetAccessTokenSession(ctx, sig, session)
	if err != nil {
		t.Fatalf("GetAccessTokenSession: %v", err)
	}
	if got.GetID() != req.ID {
		t.Errorf("ID mismatch")
	}

	err = store.DeleteAccessTokenSession(ctx, sig)
	if err != nil {
		t.Fatalf("DeleteAccessTokenSession: %v", err)
	}
}

func TestFositeStorage_RefreshToken_CRUD(t *testing.T) {
	ctx := context.Background()
	store := NewFositeStorage(testPool)

	sig := "rt-sig-" + uuid.New().String()
	req := &fosite.Request{
		ID:          uuid.New().String(),
		RequestedAt: time.Now().UTC(),
		Client:      &fosite.DefaultClient{ID: "c1"},
	}

	err := store.CreateRefreshTokenSession(ctx, sig, "access-sig", req)
	if err != nil {
		t.Fatalf("CreateRefreshTokenSession: %v", err)
	}

	session := &fosite.DefaultSession{}
	got, err := store.GetRefreshTokenSession(ctx, sig, session)
	if err != nil {
		t.Fatalf("GetRefreshTokenSession: %v", err)
	}
	if got.GetID() != req.ID {
		t.Errorf("ID mismatch")
	}

	err = store.DeleteRefreshTokenSession(ctx, sig)
	if err != nil {
		t.Fatalf("DeleteRefreshTokenSession: %v", err)
	}

	_, err = store.GetRefreshTokenSession(ctx, sig, nil)
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestFositeStorage_OpenIDConnectSession(t *testing.T) {
	ctx := context.Background()
	store := NewFositeStorage(testPool)

	code := "oidc-code-" + uuid.New().String()
	req := &fosite.Request{
		ID:          uuid.New().String(),
		RequestedAt: time.Now().UTC(),
		Client:      &fosite.DefaultClient{ID: "c1"},
		Session:     &fosite.DefaultSession{Subject: "user-1"},
	}

	err := store.CreateOpenIDConnectSession(ctx, code, req)
	if err != nil {
		t.Fatalf("CreateOpenIDConnectSession: %v", err)
	}

	got, err := store.GetOpenIDConnectSession(ctx, code, nil)
	if err != nil {
		t.Fatalf("GetOpenIDConnectSession: %v", err)
	}
	if got.GetID() != req.ID {
		t.Errorf("ID mismatch")
	}

	err = store.DeleteOpenIDConnectSession(ctx, code)
	if err != nil {
		t.Fatalf("DeleteOpenIDConnectSession: %v", err)
	}
}

func TestFositeStorage_ClientAssertionJWT(t *testing.T) {
	ctx := context.Background()
	store := NewFositeStorage(testPool)

	jti := uuid.New().String()

	// First time: should be valid
	err := store.ClientAssertionJWTValid(ctx, jti)
	if err != nil {
		t.Fatalf("ClientAssertionJWTValid (first): %v", err)
	}

	// Record it
	err = store.SetClientAssertionJWT(ctx, jti, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("SetClientAssertionJWT: %v", err)
	}

	// Second time: should be invalid (already seen)
	err = store.ClientAssertionJWTValid(ctx, jti)
	if err != fosite.ErrNotFound {
		t.Errorf("expected fosite.ErrNotFound for reused JTI, got %v", err)
	}
}
