package service

import (
	"context"
	"strings"
	"testing"

	"github.com/zeal/auth/internal/repository"
)

func cleanUsersForAuth(t *testing.T) {
	t.Helper()
	_, err := testPool.Exec(context.Background(), "DELETE FROM auth.users")
	if err != nil {
		t.Fatalf("clean users: %v", err)
	}
}

func setupAuthService(t *testing.T) *AuthService {
	t.Helper()
	cleanUsersForAuth(t)
	userRepo := repository.NewUserRepository(testPool)
	return NewAuthService(userRepo)
}

func TestSignup_Success(t *testing.T) {
	svc := setupAuthService(t)
	ctx := context.Background()

	result, err := svc.Signup(ctx, "new@example.com", "password123")
	if err != nil {
		t.Fatalf("Signup: %v", err)
	}
	if result.User.Email != "new@example.com" {
		t.Errorf("Email = %q, want %q", result.User.Email, "new@example.com")
	}
	if result.User.EmailVerified {
		t.Error("should be unverified")
	}
}

func TestSignup_DuplicateEmail(t *testing.T) {
	svc := setupAuthService(t)
	ctx := context.Background()

	_, err := svc.Signup(ctx, "dup@example.com", "password123")
	if err != nil {
		t.Fatalf("first Signup: %v", err)
	}

	_, err = svc.Signup(ctx, "dup@example.com", "password123")
	if err != ErrEmailAlreadyExists {
		t.Errorf("expected ErrEmailAlreadyExists, got %v", err)
	}
}

func TestSignup_WeakPassword(t *testing.T) {
	svc := setupAuthService(t)
	ctx := context.Background()

	_, err := svc.Signup(ctx, "weak@example.com", "short")
	if err != ErrPasswordTooShort {
		t.Errorf("expected ErrPasswordTooShort, got %v", err)
	}
}

func TestSignup_InvalidEmail(t *testing.T) {
	svc := setupAuthService(t)
	ctx := context.Background()

	_, err := svc.Signup(ctx, "not-an-email", "password123")
	if err != ErrInvalidEmail {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestSignup_PasswordNotReturned(t *testing.T) {
	svc := setupAuthService(t)
	ctx := context.Background()

	result, err := svc.Signup(ctx, "nopass@example.com", "password123")
	if err != nil {
		t.Fatalf("Signup: %v", err)
	}
	if result.User.PasswordHash == nil {
		t.Fatal("PasswordHash should not be nil")
	}
	if !strings.HasPrefix(*result.User.PasswordHash, "$2") {
		t.Error("PasswordHash should start with $2 (bcrypt)")
	}
}

func TestLogin_Success(t *testing.T) {
	svc := setupAuthService(t)
	ctx := context.Background()

	_, err := svc.Signup(ctx, "login@example.com", "password123")
	if err != nil {
		t.Fatalf("Signup: %v", err)
	}

	// Verify email directly
	_, _ = testPool.Exec(ctx, `UPDATE auth.users SET email_verified = true WHERE email = 'login@example.com'`)

	result, err := svc.Login(ctx, "login@example.com", "password123")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if result.User.Email != "login@example.com" {
		t.Errorf("Email = %q, want %q", result.User.Email, "login@example.com")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	svc := setupAuthService(t)
	ctx := context.Background()

	_, err := svc.Signup(ctx, "wrong@example.com", "password123")
	if err != nil {
		t.Fatalf("Signup: %v", err)
	}

	_, err = svc.Login(ctx, "wrong@example.com", "wrongpassword")
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestLogin_UnknownEmail_SameResponse(t *testing.T) {
	svc := setupAuthService(t)
	ctx := context.Background()

	_, err := svc.Login(ctx, "unknown@example.com", "password123")
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestLogin_UnverifiedEmail(t *testing.T) {
	svc := setupAuthService(t)
	ctx := context.Background()

	_, err := svc.Signup(ctx, "unverified@example.com", "password123")
	if err != nil {
		t.Fatalf("Signup: %v", err)
	}

	_, err = svc.Login(ctx, "unverified@example.com", "password123")
	if err != ErrEmailNotVerified {
		t.Errorf("expected ErrEmailNotVerified, got %v", err)
	}
}

func TestLogin_SocialOnlyAccount(t *testing.T) {
	svc := setupAuthService(t)
	ctx := context.Background()

	// Insert a social-only user directly
	_, err := testPool.Exec(ctx,
		`INSERT INTO auth.users (email, password_hash, email_verified) VALUES ($1, NULL, true)`,
		"social@example.com",
	)
	if err != nil {
		t.Fatalf("insert social user: %v", err)
	}

	_, err = svc.Login(ctx, "social@example.com", "anypassword")
	if err != ErrSocialAccountOnly {
		t.Errorf("expected ErrSocialAccountOnly, got %v", err)
	}
}

func TestLogin_PasswordIsBcrypt(t *testing.T) {
	svc := setupAuthService(t)
	ctx := context.Background()

	_, err := svc.Signup(ctx, "bcrypt@example.com", "password123")
	if err != nil {
		t.Fatalf("Signup: %v", err)
	}

	user, _ := svc.users.GetByEmail(ctx, "bcrypt@example.com")
	if !strings.HasPrefix(*user.PasswordHash, "$2") {
		t.Error("stored hash should start with $2 (bcrypt)")
	}
}
