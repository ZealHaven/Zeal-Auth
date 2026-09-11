package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zeal/auth/internal/model"
)

var ErrFederatedIdentityNotFound = errors.New("federated identity not found")

type FederatedRepository struct {
	pool *pgxpool.Pool
}

func NewFederatedRepository(pool *pgxpool.Pool) *FederatedRepository {
	return &FederatedRepository{pool: pool}
}

func (r *FederatedRepository) FindByIdentity(ctx context.Context, provider, providerUserID string) (*model.FederatedIdentity, error) {
	fi := &model.FederatedIdentity{}
	err := r.pool.QueryRow(ctx,
		`SELECT id, user_id, provider, provider_user_id, email_at_provider, created_at
		 FROM auth.federated_identities
		 WHERE provider = $1 AND provider_user_id = $2`,
		provider, providerUserID,
	).Scan(&fi.ID, &fi.UserID, &fi.Provider, &fi.ProviderUserID, &fi.EmailAtProvider, &fi.CreatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrFederatedIdentityNotFound
		}
		return nil, err
	}
	return fi, nil
}

func (r *FederatedRepository) FindByUserID(ctx context.Context, userID uuid.UUID) ([]*model.FederatedIdentity, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, user_id, provider, provider_user_id, email_at_provider, created_at
		 FROM auth.federated_identities
		 WHERE user_id = $1`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var identities []*model.FederatedIdentity
	for rows.Next() {
		fi := &model.FederatedIdentity{}
		if err := rows.Scan(&fi.ID, &fi.UserID, &fi.Provider, &fi.ProviderUserID, &fi.EmailAtProvider, &fi.CreatedAt); err != nil {
			return nil, err
		}
		identities = append(identities, fi)
	}
	return identities, rows.Err()
}

func (r *FederatedRepository) Link(ctx context.Context, userID uuid.UUID, provider, providerUserID, email string) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO auth.federated_identities (user_id, provider, provider_user_id, email_at_provider)
		 VALUES ($1, $2, $3, $4)`,
		userID, provider, providerUserID, email,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrDuplicateEmail // unique constraint violation
		}
		return err
	}
	return nil
}

// CreateUserWithoutPassword creates a user with password_hash=NULL and email_verified=true for social logins.
func (r *FederatedRepository) CreateUserWithoutPassword(ctx context.Context, email string) (*model.User, error) {
	user := &model.User{}
	err := r.pool.QueryRow(ctx,
		`INSERT INTO auth.users (email, password_hash, email_verified)
		 VALUES ($1, NULL, true)
		 RETURNING id, email, password_hash, email_verified, created_at, updated_at`,
		email,
	).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.EmailVerified, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrDuplicateEmail
		}
		return nil, err
	}
	return user, nil
}
