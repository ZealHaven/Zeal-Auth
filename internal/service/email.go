package service

import (
	"context"
	"errors"
	"fmt"
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
	mailer       Mailer
	publicURL    string // absolute base URL for links in emails
}

func NewEmailService(
	users *repository.UserRepository,
	verification *repository.VerificationRepository,
	reset *repository.ResetRepository,
	pool *pgxpool.Pool,
	sessionSvc *SessionService,
	mailer Mailer,
	publicURL string,
) *EmailService {
	if mailer == nil {
		mailer = LogMailer{}
	}
	return &EmailService{
		users:        users,
		verification: verification,
		reset:        reset,
		pool:         pool,
		sessionSvc:   sessionSvc,
		mailer:       mailer,
		publicURL:    publicURL,
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

	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("get user for verification email: %w", err)
	}
	link := fmt.Sprintf("%s/verify?token=%s", s.publicURL, raw)
	if err := s.mailer.Send(ctx, user.Email, "Verify your email",
		"Confirm your email address by opening this link:\n\n"+link+"\n\nThis link expires in 24 hours."); err != nil {
		return "", fmt.Errorf("send verification email: %w", err)
	}
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

	link := fmt.Sprintf("%s/reset-password?token=%s", s.publicURL, raw)
	if err := s.mailer.Send(ctx, user.Email, "Reset your password",
		"Set a new password by opening this link:\n\n"+link+"\n\nThis link expires in 60 minutes."); err != nil {
		return "", 500, fmt.Errorf("send reset email: %w", err)
	}
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

	// Fosite-issued tokens live in fosite_requests keyed by session subject —
	// deleting them invalidates access + refresh tokens (AC-RESET-3)
	_, err = s.pool.Exec(ctx,
		`DELETE FROM auth.fosite_requests
		 WHERE (key LIKE 'refreshtoken:%' OR key LIKE 'accesstoken:%')
		   AND data->'session_data'->>'subject' = $1`,
		rt.UserID.String(),
	)
	if err != nil {
		return "", 500, fmt.Errorf("revoke fosite tokens: %w", err)
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
