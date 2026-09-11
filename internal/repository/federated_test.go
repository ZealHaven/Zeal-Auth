package repository

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func cleanFederated(t *testing.T) {
	t.Helper()
	_, _ = testPool.Exec(context.Background(), "DELETE FROM auth.federated_identities")
	_, _ = testPool.Exec(context.Background(), "DELETE FROM auth.users")
}

func TestFederatedRepo_Link(t *testing.T) {
	cleanFederated(t)
	ctx := context.Background()
	fedRepo := NewFederatedRepository(testPool)
	userRepo := NewUserRepository(testPool)

	user, err := userRepo.Create(ctx, "link@example.com", "")
	if err != nil {
		t.Fatalf("Create user: %v", err)
	}

	err = fedRepo.Link(ctx, user.ID, "google", "google-123", "link@example.com")
	if err != nil {
		t.Fatalf("Link: %v", err)
	}

	fi, err := fedRepo.FindByIdentity(ctx, "google", "google-123")
	if err != nil {
		t.Fatalf("FindByIdentity: %v", err)
	}
	if fi.UserID != user.ID {
		t.Errorf("UserID = %v, want %v", fi.UserID, user.ID)
	}
	if fi.Provider != "google" {
		t.Errorf("Provider = %q, want %q", fi.Provider, "google")
	}
}

func TestFederatedRepo_FindByIdentity_Found(t *testing.T) {
	cleanFederated(t)
	ctx := context.Background()
	fedRepo := NewFederatedRepository(testPool)
	userRepo := NewUserRepository(testPool)

	user, err := userRepo.Create(ctx, "found@example.com", "")
	if err != nil {
		t.Fatalf("Create user: %v", err)
	}
	if err := fedRepo.Link(ctx, user.ID, "github", "gh-456", "found@example.com"); err != nil {
		t.Fatalf("Link: %v", err)
	}

	fi, err := fedRepo.FindByIdentity(ctx, "github", "gh-456")
	if err != nil {
		t.Fatalf("FindByIdentity: %v", err)
	}
	if fi.UserID != user.ID {
		t.Errorf("UserID = %v, want %v", fi.UserID, user.ID)
	}
}

func TestFederatedRepo_FindByIdentity_NotFound(t *testing.T) {
	cleanFederated(t)
	ctx := context.Background()
	fedRepo := NewFederatedRepository(testPool)

	_, err := fedRepo.FindByIdentity(ctx, "google", "nonexistent")
	if err != ErrFederatedIdentityNotFound {
		t.Errorf("expected ErrFederatedIdentityNotFound, got %v", err)
	}
}

func TestFederatedRepo_FindByUserID(t *testing.T) {
	cleanFederated(t)
	ctx := context.Background()
	fedRepo := NewFederatedRepository(testPool)
	userRepo := NewUserRepository(testPool)

	user, err := userRepo.Create(ctx, "multi@example.com", "")
	if err != nil {
		t.Fatalf("Create user: %v", err)
	}
	if err := fedRepo.Link(ctx, user.ID, "google", "g-1", "multi@example.com"); err != nil {
		t.Fatalf("Link google: %v", err)
	}
	if err := fedRepo.Link(ctx, user.ID, "github", "gh-1", "multi@example.com"); err != nil {
		t.Fatalf("Link github: %v", err)
	}

	identities, err := fedRepo.FindByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("FindByUserID: %v", err)
	}
	if len(identities) != 2 {
		t.Errorf("len(identities) = %d, want 2", len(identities))
	}
}

func TestFederatedRepo_UniqueConstraint(t *testing.T) {
	cleanFederated(t)
	ctx := context.Background()
	fedRepo := NewFederatedRepository(testPool)
	userRepo := NewUserRepository(testPool)

	user1, _ := userRepo.Create(ctx, "u1@example.com", "")
	user2, _ := userRepo.Create(ctx, "u2@example.com", "")

	if err := fedRepo.Link(ctx, user1.ID, "google", "dup-123", "u1@example.com"); err != nil {
		t.Fatalf("first Link: %v", err)
	}

	err := fedRepo.Link(ctx, user2.ID, "google", "dup-123", "u2@example.com")
	if err == nil {
		t.Error("expected error for duplicate (provider, provider_user_id)")
	}
}

func TestFederatedRepo_CreateUserWithoutPassword(t *testing.T) {
	cleanFederated(t)
	ctx := context.Background()
	fedRepo := NewFederatedRepository(testPool)

	user, err := fedRepo.CreateUserWithoutPassword(ctx, "social@example.com")
	if err != nil {
		t.Fatalf("CreateUserWithoutPassword: %v", err)
	}
	if user.PasswordHash != nil {
		t.Error("PasswordHash should be nil for social user")
	}
	if !user.EmailVerified {
		t.Error("EmailVerified should be true for social user")
	}
	if user.Email != "social@example.com" {
		t.Errorf("Email = %q, want %q", user.Email, "social@example.com")
	}
}

func TestFederatedRepo_CreateUserWithoutPassword_Duplicate(t *testing.T) {
	cleanFederated(t)
	ctx := context.Background()
	fedRepo := NewFederatedRepository(testPool)

	_, err := fedRepo.CreateUserWithoutPassword(ctx, "dup@example.com")
	if err != nil {
		t.Fatalf("first CreateUserWithoutPassword: %v", err)
	}

	_, err = fedRepo.CreateUserWithoutPassword(ctx, "dup@example.com")
	if err != ErrDuplicateEmail {
		t.Errorf("expected ErrDuplicateEmail, got %v", err)
	}
}

func TestFederatedRepo_Link_CascadeOnUserDelete(t *testing.T) {
	cleanFederated(t)
	ctx := context.Background()
	fedRepo := NewFederatedRepository(testPool)
	userRepo := NewUserRepository(testPool)

	user, _ := userRepo.Create(ctx, "cascade@example.com", "")
	_ = fedRepo.Link(ctx, user.ID, "google", "c-1", "cascade@example.com")

	// Delete user directly (cascade)
	_, _ = testPool.Exec(ctx, "DELETE FROM auth.users WHERE id = $1", user.ID)

	_, err := fedRepo.FindByIdentity(ctx, "google", "c-1")
	if err != ErrFederatedIdentityNotFound {
		t.Errorf("expected ErrFederatedIdentityNotFound after cascade, got %v", err)
	}
}

func TestFederatedRepo_FindByUserID_Empty(t *testing.T) {
	cleanFederated(t)
	ctx := context.Background()
	fedRepo := NewFederatedRepository(testPool)

	identities, err := fedRepo.FindByUserID(ctx, uuid.New())
	if err != nil {
		t.Fatalf("FindByUserID: %v", err)
	}
	if len(identities) != 0 {
		t.Errorf("len(identities) = %d, want 0", len(identities))
	}
}
