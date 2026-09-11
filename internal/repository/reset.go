package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zeal/auth/internal/model"
)

var ErrResetTokenNotFound = errors.New("reset token not found")

type ResetRepository struct {
	pool *pgxpool.Pool
}

func NewResetRepository(pool *pgxpool.Pool) *ResetRepository {
	return &ResetRepository{pool: pool}
}

func (r *ResetRepository) Create(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO auth.password_reset_tokens (user_id, token_hash, expires_at)
		 VALUES ($1, $2, $3)`,
		userID, tokenHash, expiresAt,
	)
	return err
}

func (r *ResetRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*model.ResetToken, error) {
	t := &model.ResetToken{}
	err := r.pool.QueryRow(ctx,
		`SELECT id, user_id, token_hash, expires_at, used_at, created_at
		 FROM auth.password_reset_tokens WHERE token_hash = $1`,
		tokenHash,
	).Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrResetTokenNotFound
		}
		return nil, err
	}
	return t, nil
}

func (r *ResetRepository) MarkUsed(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE auth.password_reset_tokens SET used_at = now() WHERE id = $1`,
		id,
	)
	return err
}
