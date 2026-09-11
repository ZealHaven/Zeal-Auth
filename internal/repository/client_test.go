package repository

import (
	"context"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func cleanClients(t *testing.T) {
	t.Helper()
	_, _ = testPool.Exec(context.Background(), "DELETE FROM auth.client_redirect_uris")
	_, _ = testPool.Exec(context.Background(), "DELETE FROM auth.clients")
}

func TestClientRepo_Create(t *testing.T) {
	cleanClients(t)
	ctx := context.Background()
	repo := NewClientRepository(testPool)

	hash, _ := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)
	err := repo.Create(ctx, "test-client", string(hash), "Test Client", []string{
		"http://localhost:3000/callback",
		"https://app.example.com/callback",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	client, err := repo.GetClient(ctx, "test-client")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if client.Name != "Test Client" {
		t.Errorf("Name = %q, want %q", client.Name, "Test Client")
	}
	if client.Status != "active" {
		t.Errorf("Status = %q, want %q", client.Status, "active")
	}
}

func TestClientRepo_GetClient(t *testing.T) {
	cleanClients(t)
	ctx := context.Background()
	repo := NewClientRepository(testPool)

	_, err := repo.GetClient(ctx, "nonexistent")
	if err != ErrClientNotFound {
		t.Errorf("expected ErrClientNotFound, got %v", err)
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)
	_ = repo.Create(ctx, "exists", string(hash), "Exists", []string{"http://localhost"})
	client, err := repo.GetClient(ctx, "exists")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if client.ID != "exists" {
		t.Errorf("ID = %q, want %q", client.ID, "exists")
	}
}

func TestClientRepo_DisableClient(t *testing.T) {
	cleanClients(t)
	ctx := context.Background()
	repo := NewClientRepository(testPool)

	hash, _ := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)
	_ = repo.Create(ctx, "disable-me", string(hash), "Disable Me", []string{"http://localhost"})

	err := repo.DisableClient(ctx, "disable-me")
	if err != nil {
		t.Fatalf("DisableClient: %v", err)
	}

	client, err := repo.GetClient(ctx, "disable-me")
	if err != nil {
		t.Fatalf("GetClient after disable: %v", err)
	}
	if client.Status != "disabled" {
		t.Errorf("Status = %q, want %q", client.Status, "disabled")
	}
}

func TestClientRepo_DisableClient_NotFound(t *testing.T) {
	cleanClients(t)
	ctx := context.Background()
	repo := NewClientRepository(testPool)

	err := repo.DisableClient(ctx, "nonexistent")
	if err != ErrClientNotFound {
		t.Errorf("expected ErrClientNotFound, got %v", err)
	}
}

func TestClientRepo_GetRedirectURIs(t *testing.T) {
	cleanClients(t)
	ctx := context.Background()
	repo := NewClientRepository(testPool)

	hash, _ := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)
	_ = repo.Create(ctx, "uris-client", string(hash), "URIs Client", []string{
		"http://localhost:3000/cb",
		"https://app.example.com/cb",
	})

	uris, err := repo.GetRedirectURIs(ctx, "uris-client")
	if err != nil {
		t.Fatalf("GetRedirectURIs: %v", err)
	}
	if len(uris) != 2 {
		t.Errorf("len(uris) = %d, want 2", len(uris))
	}
}

func TestClientRepo_DuplicateID_Fails(t *testing.T) {
	cleanClients(t)
	ctx := context.Background()
	repo := NewClientRepository(testPool)

	hash, _ := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)
	err := repo.Create(ctx, "dup-id", string(hash), "First", []string{"http://localhost"})
	if err != nil {
		t.Fatalf("first Create: %v", err)
	}

	err = repo.Create(ctx, "dup-id", string(hash), "Second", []string{"http://localhost"})
	if err != ErrDuplicateClientID {
		t.Errorf("expected ErrDuplicateClientID, got %v", err)
	}
}
