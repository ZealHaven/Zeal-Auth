// Command seed provisions dev data directly in Postgres (no server needed):
//
//	seed                                             test user + two demo clients (just seed)
//	seed client <name> <redirect-uri>                one client, secret printed once (just seed-client)
//
// Secrets are bcrypt-hashed before insert and shown exactly once on stdout —
// never persisted in plaintext (1-mvp.md §2, AC-3-5).
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/zeal/auth/internal/config"
)

func main() {
	cfg := config.Load()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		fatal("connect db: %v", err)
	}
	defer pool.Close()

	args := os.Args[1:]
	switch {
	case len(args) == 0:
		seedDefaults(pool)
	case args[0] == "client" && len(args) >= 3:
		// just re-splits quoted args, so the last arg is the URI and
		// everything before it rejoins into the display name
		rest := args[1:]
		seedClient(pool, strings.Join(rest[:len(rest)-1], " "), rest[len(rest)-1])
	default:
		fmt.Fprintln(os.Stderr, "usage: seed | seed client <name> <redirect-uri>")
		os.Exit(2)
	}
}

func seedDefaults(pool *pgxpool.Pool) {
	ctx := context.Background()
	// Verified dev user — login works immediately after `just seed` (3.3, AC-3-4)
	hash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	if err != nil {
		fatal("hash user password: %v", err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO auth.users (email, password_hash, email_verified)
		 VALUES ('dev@example.com', $1, true)
		 ON CONFLICT (email) DO NOTHING`,
		string(hash),
	)
	if err != nil {
		fatal("insert dev user: %v", err)
	}
	fmt.Println("user:      dev@example.com / password123 (verified)")

	// Two clients so silent SSO can be checked by hand (3.4, AC-3-3)
	seedClient(pool, "demo-a", "http://localhost:3001/callback")
	seedClient(pool, "demo-b", "http://localhost:3002/callback")
}

func seedClient(pool *pgxpool.Pool, name, redirectURI string) {
	id := slug(name)
	secret := randomSecret()
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		fatal("hash client secret: %v", err)
	}

	ctx := context.Background()
	_, err = pool.Exec(ctx,
		`INSERT INTO auth.clients (id, client_secret_hash, name)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (id) DO UPDATE SET client_secret_hash = EXCLUDED.client_secret_hash, name = EXCLUDED.name`,
		id, string(hash), name,
	)
	if err != nil {
		fatal("insert client %s: %v", id, err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO auth.client_redirect_uris (client_id, redirect_uri)
		 VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		id, redirectURI,
	)
	if err != nil {
		fatal("insert redirect uri: %v", err)
	}

	// Shown once at creation (AC-3-1, AC-3-5) — hashed copy is all that persists
	fmt.Printf("client_id:      %s\n", id)
	fmt.Printf("client_secret:  %s  (shown once — store it now)\n", secret)
	fmt.Printf("redirect_uri:   %s\n", redirectURI)
}

var slugStrip = regexp.MustCompile(`[^a-z0-9]+`)

func slug(name string) string {
	s := slugStrip.ReplaceAllString(strings.ToLower(name), "-")
	return strings.Trim(s, "-")
}

func randomSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		fatal("generate secret: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "seed: "+format+"\n", args...)
	os.Exit(1)
}
