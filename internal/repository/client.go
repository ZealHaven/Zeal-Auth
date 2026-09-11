package repository

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zeal/auth/internal/model"
)

var ErrDuplicateClientID = errors.New("duplicate client_id")
var ErrClientNotFound = errors.New("client not found")

type ClientRepository struct {
	pool *pgxpool.Pool
}

func NewClientRepository(pool *pgxpool.Pool) *ClientRepository {
	return &ClientRepository{pool: pool}
}

func (r *ClientRepository) Create(ctx context.Context, id, secretHash, name string, redirectURIs []string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx,
		`INSERT INTO auth.clients (id, client_secret_hash, name) VALUES ($1, $2, $3)`,
		id, secretHash, name,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrDuplicateClientID
		}
		return err
	}

	for _, uri := range redirectURIs {
		_, err = tx.Exec(ctx,
			`INSERT INTO auth.client_redirect_uris (client_id, redirect_uri) VALUES ($1, $2)`,
			id, uri,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (r *ClientRepository) GetClient(ctx context.Context, id string) (*model.Client, error) {
	c := &model.Client{}
	err := r.pool.QueryRow(ctx,
		`SELECT id, client_secret_hash, name, status, created_at
		 FROM auth.clients WHERE id = $1`,
		id,
	).Scan(&c.ID, &c.ClientSecretHash, &c.Name, &c.Status, &c.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrClientNotFound
		}
		return nil, err
	}
	return c, nil
}

func (r *ClientRepository) DisableClient(ctx context.Context, id string) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE auth.clients SET status = 'disabled' WHERE id = $1`,
		id,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrClientNotFound
	}
	return nil
}

func (r *ClientRepository) GetRedirectURIs(ctx context.Context, clientID string) ([]string, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT redirect_uri FROM auth.client_redirect_uris WHERE client_id = $1`,
		clientID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var uris []string
	for rows.Next() {
		var uri string
		if err := rows.Scan(&uri); err != nil {
			return nil, err
		}
		uris = append(uris, uri)
	}
	return uris, rows.Err()
}
