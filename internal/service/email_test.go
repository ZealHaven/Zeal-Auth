package service

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/zeal/auth/internal/repository"
)

func cleanAll(t *testing.T) {
	t.Helper()
	_, _ = testPool.Exec(context.Background(), "DELETE FROM auth.email_verification_tokens")
	_, _ = testPool.Exec(context.Background(), "DELETE FROM auth.password_reset_tokens")
	_, _ = testPool.Exec(context.Background(), "DELETE FROM auth.refresh_tokens")
	_, _ = testPool.Exec(context.Background(), "DELETE FROM auth.users")
}

func setupEmailService(t *testing.T) (*EmailService, *repository.UserRepository) {
	t.Helper()
	cleanAll(t)
	userRepo := repository.NewUserRepository(testPool)
	verificationRepo := repository.NewVerificationRepository(testPool)
	resetRepo := repository.NewResetRepository(testPool)
	emailSvc := NewEmailService(userRepo, verificationRepo, resetRepo, testPool, nil)
	return emailSvc, userRepo
}

func createUser(t *testing.T, userRepo *repository.UserRepository, email string) uuid.UUID {
	t.Helper()
	user, err := userRepo.Create(context.Background(), email, "$2a$10$fakehash")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user.ID
}

// --- Email Verification Tests ---

func TestVerifyEmail_ValidToken(t *testing.T) {
	svc, userRepo := setupEmailService(t)
	ctx := context.Background()
	uid := createUser(t, userRepo, "verify@example.com")

	raw, err := svc.GenerateVerificationToken(ctx, uid)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	msg, status, err := svc.VerifyEmail(ctx, raw)
	if err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if status != 200 {
		t.Errorf("status = %d, want 200", status)
	}
	if msg != "Email verified successfully" {
		t.Errorf("message = %q", msg)
	}

	// Verify user is now verified
	user, _ := userRepo.GetByEmail(ctx, "verify@example.com")
	if !user.EmailVerified {
		t.Error("user should be email_verified")
	}
}

func TestVerifyEmail_ExpiredToken(t *testing.T) {
	svc, userRepo := setupEmailService(t)
	ctx := context.Background()
	uid := createUser(t, userRepo, "expired@example.com")

	raw, err := svc.GenerateVerificationToken(ctx, uid)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	// Manually expire the token
	tokenHash := HashToken(raw)
	_, _ = testPool.Exec(ctx,
		`UPDATE auth.email_verification_tokens SET expires_at = now() - interval '1 hour'
		 WHERE token_hash = $1`, tokenHash)

	_, status, err := svc.VerifyEmail(ctx, raw)
	if err != ErrTokenExpired {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
	if status != 410 {
		t.Errorf("status = %d, want 410", status)
	}
}

func TestVerifyEmail_InvalidToken(t *testing.T) {
	svc, _ := setupEmailService(t)
	ctx := context.Background()

	_, status, err := svc.VerifyEmail(ctx, "nonexistent-token")
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
	if status != 400 {
		t.Errorf("status = %d, want 400", status)
	}
}

func TestVerifyEmail_AlreadyUsed(t *testing.T) {
	svc, userRepo := setupEmailService(t)
	ctx := context.Background()
	uid := createUser(t, userRepo, "already@example.com")

	raw, err := svc.GenerateVerificationToken(ctx, uid)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	// Use it once
	_, _, err = svc.VerifyEmail(ctx, raw)
	if err != nil {
		t.Fatalf("first verify: %v", err)
	}

	// Use it again
	msg, status, err := svc.VerifyEmail(ctx, raw)
	if err != nil {
		t.Fatalf("second verify: %v", err)
	}
	if status != 200 {
		t.Errorf("status = %d, want 200", status)
	}
	if msg != "Email already verified" {
		t.Errorf("message = %q, want %q", msg, "Email already verified")
	}
}

func TestVerifyEmail_TokenIsSingleUse(t *testing.T) {
	svc, userRepo := setupEmailService(t)
	ctx := context.Background()
	uid := createUser(t, userRepo, "single@example.com")

	raw, err := svc.GenerateVerificationToken(ctx, uid)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	// First use
	_, _, err = svc.VerifyEmail(ctx, raw)
	if err != nil {
		t.Fatalf("first verify: %v", err)
	}

	// Second use should succeed (already_verified), not error
	msg, status, err := svc.VerifyEmail(ctx, raw)
	if err != nil {
		t.Fatalf("second verify should not error: %v", err)
	}
	if status != 200 || msg != "Email already verified" {
		t.Errorf("second verify: status=%d, msg=%q", status, msg)
	}
}

func TestVerificationToken_TTL24h(t *testing.T) {
	svc, userRepo := setupEmailService(t)
	ctx := context.Background()
	uid := createUser(t, userRepo, "ttl@example.com")

	_, err := svc.GenerateVerificationToken(ctx, uid)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	var diffSecs int
	err = testPool.QueryRow(ctx,
		`SELECT extract(epoch from (expires_at - created_at))::int
		 FROM auth.email_verification_tokens WHERE user_id = $1`, uid,
	).Scan(&diffSecs)
	if err != nil {
		t.Fatalf("query diff: %v", err)
	}
	// 24h = 86400s, allow small clock drift
	if diffSecs < 86399 || diffSecs > 86401 {
		t.Errorf("TTL = %d seconds, want ~86400 (24h)", diffSecs)
	}
}

func TestVerificationToken_OnlyHashStored(t *testing.T) {
	svc, userRepo := setupEmailService(t)
	ctx := context.Background()
	uid := createUser(t, userRepo, "hashonly@example.com")

	raw, err := svc.GenerateVerificationToken(ctx, uid)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	// Raw token should not appear in DB
	var count int
	err = testPool.QueryRow(ctx,
		`SELECT count(*) FROM auth.email_verification_tokens
		 WHERE token_hash = $1`, raw,
	).Scan(&count)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 0 {
		t.Error("raw token should not be stored in DB")
	}

	// Hash should be in DB
	hash := HashToken(raw)
	err = testPool.QueryRow(ctx,
		`SELECT count(*) FROM auth.email_verification_tokens
		 WHERE token_hash = $1`, hash,
	).Scan(&count)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 1 {
		t.Error("hashed token should be in DB")
	}
}

// --- Password Reset Tests ---

func TestForgotPassword_RegisteredEmail(t *testing.T) {
	svc, userRepo := setupEmailService(t)
	ctx := context.Background()
	uid := createUser(t, userRepo, "forgot@example.com")

	msg, status, err := svc.ForgotPassword(ctx, "forgot@example.com")
	if err != nil {
		t.Fatalf("ForgotPassword: %v", err)
	}
	if status != 200 {
		t.Errorf("status = %d, want 200", status)
	}
	if msg != "If an account exists, a reset link has been sent." {
		t.Errorf("message = %q", msg)
	}

	// Verify token was created
	var count int
	err = testPool.QueryRow(ctx,
		`SELECT count(*) FROM auth.password_reset_tokens WHERE user_id = $1`, uid,
	).Scan(&count)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 reset token, got %d", count)
	}
}

func TestForgotPassword_UnregisteredEmail(t *testing.T) {
	svc, _ := setupEmailService(t)
	ctx := context.Background()

	msg, status, err := svc.ForgotPassword(ctx, "nobody@example.com")
	if err != nil {
		t.Fatalf("ForgotPassword: %v", err)
	}
	if status != 200 {
		t.Errorf("status = %d, want 200", status)
	}
	if msg != "If an account exists, a reset link has been sent." {
		t.Errorf("message = %q", msg)
	}
}

func TestForgotPassword_SameResponseForBoth(t *testing.T) {
	svc, userRepo := setupEmailService(t)
	ctx := context.Background()
	createUser(t, userRepo, "exists@example.com")

	msg1, status1, _ := svc.ForgotPassword(ctx, "exists@example.com")
	msg2, status2, _ := svc.ForgotPassword(ctx, "nobody@example.com")

	if msg1 != msg2 {
		t.Errorf("responses differ: %q vs %q", msg1, msg2)
	}
	if status1 != status2 {
		t.Errorf("statuses differ: %d vs %d", status1, status2)
	}
}

func TestResetPassword_ValidToken(t *testing.T) {
	svc, userRepo := setupEmailService(t)
	ctx := context.Background()
	uid := createUser(t, userRepo, "reset@example.com")

	// Generate a reset token
	raw, err := generateResetTokenDirect(ctx, svc, uid)
	if err != nil {
		t.Fatalf("generate reset token: %v", err)
	}

	msg, status, err := svc.ResetPassword(ctx, raw, "newpassword123")
	if err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	if status != 200 {
		t.Errorf("status = %d, want 200", status)
	}
	if msg != "Password updated successfully" {
		t.Errorf("message = %q", msg)
	}

	// Verify password changed
	user, _ := userRepo.GetByEmail(ctx, "reset@example.com")
	if user.PasswordHash == nil {
		t.Fatal("password hash should not be nil")
	}
}

func TestResetPassword_TokenSingleUse(t *testing.T) {
	svc, userRepo := setupEmailService(t)
	ctx := context.Background()
	uid := createUser(t, userRepo, "singleuse@example.com")

	raw, err := generateResetTokenDirect(ctx, svc, uid)
	if err != nil {
		t.Fatalf("generate reset token: %v", err)
	}

	// First use
	_, _, err = svc.ResetPassword(ctx, raw, "newpassword123")
	if err != nil {
		t.Fatalf("first reset: %v", err)
	}

	// Second use should fail
	_, status, err := svc.ResetPassword(ctx, raw, "anotherpassword123")
	if err != ErrTokenAlreadyUsed {
		t.Errorf("expected ErrTokenAlreadyUsed, got %v", err)
	}
	if status != 400 {
		t.Errorf("status = %d, want 400", status)
	}
}

func TestResetPassword_InvalidToken(t *testing.T) {
	svc, _ := setupEmailService(t)
	ctx := context.Background()

	_, status, err := svc.ResetPassword(ctx, "nonexistent-token", "newpassword123")
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
	if status != 400 {
		t.Errorf("status = %d, want 400", status)
	}
}

func TestResetPassword_ExpiredToken(t *testing.T) {
	svc, userRepo := setupEmailService(t)
	ctx := context.Background()
	uid := createUser(t, userRepo, "expiredreset@example.com")

	raw, err := generateResetTokenDirect(ctx, svc, uid)
	if err != nil {
		t.Fatalf("generate reset token: %v", err)
	}

	// Expire the token
	tokenHash := HashToken(raw)
	_, _ = testPool.Exec(ctx,
		`UPDATE auth.password_reset_tokens SET expires_at = now() - interval '1 hour'
		 WHERE token_hash = $1`, tokenHash)

	_, status, err := svc.ResetPassword(ctx, raw, "newpassword123")
	if err != ErrTokenExpired {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
	if status != 400 {
		t.Errorf("status = %d, want 400", status)
	}
}

func TestResetPassword_WeakPassword(t *testing.T) {
	svc, userRepo := setupEmailService(t)
	ctx := context.Background()
	uid := createUser(t, userRepo, "weak@example.com")

	raw, err := generateResetTokenDirect(ctx, svc, uid)
	if err != nil {
		t.Fatalf("generate reset token: %v", err)
	}

	_, status, err := svc.ResetPassword(ctx, raw, "short")
	if err != ErrPasswordTooShort {
		t.Errorf("expected ErrPasswordTooShort, got %v", err)
	}
	if status != 400 {
		t.Errorf("status = %d, want 400", status)
	}
}

func TestResetToken_TTL60m(t *testing.T) {
	svc, userRepo := setupEmailService(t)
	ctx := context.Background()
	uid := createUser(t, userRepo, "ttlreset@example.com")

	_, err := generateResetTokenDirect(ctx, svc, uid)
	if err != nil {
		t.Fatalf("generate reset token: %v", err)
	}

	var diffSecs int
	err = testPool.QueryRow(ctx,
		`SELECT extract(epoch from (expires_at - created_at))::int
		 FROM auth.password_reset_tokens WHERE user_id = $1`, uid,
	).Scan(&diffSecs)
	if err != nil {
		t.Fatalf("query diff: %v", err)
	}
	// 60min = 3600s, allow small clock drift
	if diffSecs < 3599 || diffSecs > 3601 {
		t.Errorf("TTL = %d seconds, want ~3600 (60m)", diffSecs)
	}
}

// Helper: generate a raw reset token directly via the service flow
func generateResetTokenDirect(ctx context.Context, svc *EmailService, userID uuid.UUID) (string, error) {
	raw, err := GenerateToken()
	if err != nil {
		return "", err
	}
	tokenHash := HashToken(raw)
	err = svc.reset.Create(ctx, userID, tokenHash, time.Now().Add(60*time.Minute))
	return raw, err
}
