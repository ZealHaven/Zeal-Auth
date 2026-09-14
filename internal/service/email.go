package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/zeal/auth/internal/repository"
)

var (
	ErrInvalidToken     = errors.New("invalid_token")
	ErrTokenExpired     = errors.New("token_expired")
	ErrTokenAlreadyUsed = errors.New("token_already_used")
)

type EmailService struct {
	users        *repository.UserRepository
	verification *repository.VerificationRepository
	reset        *repository.ResetRepository
	pool         *pgxpool.Pool
	sessionSvc   *SessionService
}

func NewEmailService(
	users *repository.UserRepository,
	verification *repository.VerificationRepository,
	reset *repository.ResetRepository,
	pool *pgxpool.Pool,
	sessionSvc *SessionService,
) *EmailService {
	return &EmailService{
		users:        users,
		verification: verification,
		reset:        reset,
		pool:         pool,
		sessionSvc:   sessionSvc,
	}
}

// GenerateVerificationToken creates a verification token for a user on signup.
func (s *EmailService) GenerateVerificationToken(ctx context.Context, userID uuid.UUID) (string, error) {
	raw, err := GenerateToken()
	if err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}

	tokenHash := HashToken(raw)
	expiresAt := time.Now().Add(24 * time.Hour)

	if err := s.verification.Create(ctx, userID, tokenHash, expiresAt); err != nil {
		return "", fmt.Errorf("store verification token: %w", err)
	}

	log.Printf("[EMAIL] Verification URL: GET /verify?token=%s", raw)
	return raw, nil
}

func (s *EmailService) VerifyEmail(ctx context.Context, token string) (string, int, error) {
	tokenHash := HashToken(token)

	vt, err := s.verification.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, repository.ErrVerificationTokenNotFound) {
			return "", 400, ErrInvalidToken
		}
		return "", 500, err
	}

	if vt.UsedAt != nil {
		return "Email already verified", 200, nil
	}

	if time.Now().After(vt.ExpiresAt) {
		return "", 410, ErrTokenExpired
	}

	if err := s.verification.MarkUsed(ctx, vt.ID); err != nil {
		return "", 500, err
	}

	if err := s.users.MarkEmailVerified(ctx, vt.UserID); err != nil {
		return "", 500, err
	}

	return "Email verified successfully", 200, nil
}

func (s *EmailService) ForgotPassword(ctx context.Context, email string) (string, int, error) {
	standardMsg := "If an account exists, a reset link has been sent."

	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return standardMsg, 200, nil
		}
		return "", 500, err
	}

	raw, err := GenerateToken()
	if err != nil {
		return "", 500, fmt.Errorf("generate token: %w", err)
	}

	tokenHash := HashToken(raw)
	expiresAt := time.Now().Add(60 * time.Minute)

	if err := s.reset.Create(ctx, user.ID, tokenHash, expiresAt); err != nil {
		return "", 500, fmt.Errorf("store reset token: %w", err)
	}

	log.Printf("[EMAIL] Password reset URL: POST /reset-password token=%s", raw)
	return standardMsg, 200, nil
}

func (s *EmailService) ResetPassword(ctx context.Context, token, newPassword string) (string, int, error) {
	if len(newPassword) < 8 {
		return "", 400, ErrPasswordTooShort
	}

	tokenHash := HashToken(token)

	rt, err := s.reset.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, repository.ErrResetTokenNotFound) {
			return "", 400, ErrInvalidToken
		}
		return "", 500, err
	}

	if rt.UsedAt != nil {
		return "", 400, ErrTokenAlreadyUsed
	}

	if time.Now().After(rt.ExpiresAt) {
		return "", 400, ErrTokenExpired
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", 500, fmt.Errorf("hash password: %w", err)
	}

	_, err = s.pool.Exec(ctx,
		`UPDATE auth.users SET password_hash = $1, updated_at = now() WHERE id = $2`,
		string(hash), rt.UserID,
	)
	if err != nil {
		return "", 500, fmt.Errorf("update password: %w", err)
	}

	// Revoke all refresh tokens for this user (AC-RESET-3)
	_, err = s.pool.Exec(ctx,
		`UPDATE auth.refresh_tokens SET revoked_at = now()
		 WHERE user_id = $1 AND revoked_at IS NULL`,
		rt.UserID,
	)
	if err != nil {
		return "", 500, fmt.Errorf("revoke refresh tokens: %w", err)
	}

	if err := s.reset.MarkUsed(ctx, rt.ID); err != nil {
		return "", 500, err
	}

	// Delete all sessions for this user (AC-SESSION-4)
	if s.sessionSvc != nil {
		_ = s.sessionSvc.DeleteAllForUser(ctx, rt.UserID.String())
	}

	return "Password updated successfully", 200, nil
}
