package db

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestURL returns the database URL tests must use. Tests NEVER touch the
// dev/prod database — they get their own (default: auth_test), so TestMain
// can drop schemas freely.
func TestURL() string {
	if u := os.Getenv("TEST_DATABASE_URL"); u != "" {
		return u
	}
	return "postgres://auth:auth@localhost:5435/auth_test?sslmode=disable"
}

// EnsureTestDatabase creates the test database if missing. Safe under
// concurrent test packages (duplicate_database is ignored).
func EnsureTestDatabase(ctx context.Context) error {
	testURL := TestURL()
	u, err := url.Parse(testURL)
	if err != nil {
		return fmt.Errorf("parse test url: %w", err)
	}
	dbName := u.Path[1:]
	if dbName == "" {
		return fmt.Errorf("test url has no database name")
	}

	admin := *u
	admin.Path = "/postgres"
	adminPool, err := pgxpool.ParseConfig(admin.String())
	if err != nil {
		return fmt.Errorf("parse admin url: %w", err)
	}
	conn, err := pgxpool.NewWithConfig(ctx, adminPool)
	if err != nil {
		return fmt.Errorf("connect admin: %w", err)
	}
	defer conn.Close()

	_, err = conn.Exec(ctx, fmt.Sprintf("CREATE DATABASE %s", pgx.Identifier{dbName}.Sanitize()))
	if err != nil && !isDuplicateDB(err) {
		return fmt.Errorf("create test database: %w", err)
	}
	return nil
}

func isDuplicateDB(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42P04"
}
