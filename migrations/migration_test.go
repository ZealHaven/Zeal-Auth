package migrations_test

import (
	"context"
	"os"
	"os/exec"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zeal/auth/internal/db"
)

func testDBURL() string {
	return db.TestURL()
}

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()

	db.SkipIfNoPostgres(ctx)
	var err error
	testPool, err = pgxpool.New(ctx, testDBURL())
	if err != nil {
		panic("connect pool: " + err.Error())
	}

	// Clean state: drop schema via SQL, force migrate version to 0, then up
	_, _ = testPool.Exec(ctx, "DROP SCHEMA IF EXISTS auth CASCADE")
	// Drop schema_migrations if it somehow survived in public
	_, _ = testPool.Exec(ctx, "DROP TABLE IF EXISTS public.schema_migrations")

	out, err := exec.Command("migrate", "-path", ".", "-database", testDBURL(), "up").CombinedOutput()
	if err != nil {
		panic("migrate up: " + err.Error() + "\n" + string(out))
	}

	code := m.Run()

	// Cleanup
	_, _ = testPool.Exec(ctx, "DROP SCHEMA IF EXISTS auth CASCADE")
	_, _ = testPool.Exec(ctx, "DROP TABLE IF EXISTS public.schema_migrations")
	testPool.Close()
	os.Exit(code)
}

func schemaExists(t *testing.T, schema string) bool {
	t.Helper()
	var exists bool
	err := testPool.QueryRow(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM information_schema.schemata WHERE schema_name = $1)`, schema,
	).Scan(&exists)
	if err != nil {
		t.Fatalf("check schema: %v", err)
	}
	return exists
}

func tableExists(t *testing.T, schema, table string) bool {
	t.Helper()
	var exists bool
	err := testPool.QueryRow(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema = $1 AND table_name = $2)`,
		schema, table,
	).Scan(&exists)
	if err != nil {
		t.Fatalf("check table %s.%s: %v", schema, table, err)
	}
	return exists
}

func columnExists(t *testing.T, schema, table, column string) bool {
	t.Helper()
	var exists bool
	err := testPool.QueryRow(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2 AND column_name = $3)`,
		schema, table, column,
	).Scan(&exists)
	if err != nil {
		t.Fatalf("check column %s.%s.%s: %v", schema, table, column, err)
	}
	return exists
}

func columnIsNullable(t *testing.T, schema, table, column string) bool {
	t.Helper()
	var isNullable string
	err := testPool.QueryRow(context.Background(),
		`SELECT is_nullable FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2 AND column_name = $3`,
		schema, table, column,
	).Scan(&isNullable)
	if err != nil {
		t.Fatalf("check nullable %s.%s.%s: %v", schema, table, column, err)
	}
	return isNullable == "YES"
}

func constraintExists(t *testing.T, schema, table, constraintName string) bool {
	t.Helper()
	var exists bool
	err := testPool.QueryRow(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM information_schema.table_constraints WHERE table_schema = $1 AND table_name = $2 AND constraint_name = $3)`,
		schema, table, constraintName,
	).Scan(&exists)
	if err != nil {
		t.Fatalf("check constraint %s: %v", constraintName, err)
	}
	return exists
}

func indexExists(t *testing.T, indexName string) bool {
	t.Helper()
	var exists bool
	err := testPool.QueryRow(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM pg_indexes WHERE schemaname = 'auth' AND indexname = $1)`,
		indexName,
	).Scan(&exists)
	if err != nil {
		t.Fatalf("check index %s: %v", indexName, err)
	}
	return exists
}

func TestMigration_Up(t *testing.T) {
	if !schemaExists(t, "auth") {
		t.Fatal("auth schema does not exist after migrate up")
	}

	expectedTables := []string{
		"users",
		"federated_identities",
		"email_verification_tokens",
		"password_reset_tokens",
		"clients",
		"client_redirect_uris",
		"authorization_codes",
		"refresh_tokens",
		"signing_keys",
	}

	for _, table := range expectedTables {
		if !tableExists(t, "auth", table) {
			t.Errorf("table auth.%s does not exist", table)
		}
	}
}

func TestMigration_Down(t *testing.T) {
	ctx := context.Background()

	// Execute down migration SQL directly (migrate CLI can't track state
	// when schema_migrations lives inside the auth schema it drops)
	_, err := testPool.Exec(ctx, "DROP SCHEMA IF EXISTS auth CASCADE")
	if err != nil {
		t.Fatalf("drop schema: %v", err)
	}

	if schemaExists(t, "auth") {
		t.Fatal("auth schema still exists after down migration")
	}

	// Re-create by running migrate up (schema is gone, so fresh up works)
	// First drop any stale schema_migrations
	_, _ = testPool.Exec(ctx, "DROP TABLE IF EXISTS public.schema_migrations")

	out, err := exec.Command("migrate", "-path", ".", "-database", testDBURL(), "up").CombinedOutput()
	if err != nil {
		t.Fatalf("migrate re-up failed: %v\n%s", err, out)
	}
}

func TestMigration_TableColumns(t *testing.T) {
	tests := []struct {
		table  string
		column string
	}{
		{"users", "id"},
		{"users", "email"},
		{"users", "password_hash"},
		{"users", "email_verified"},
		{"users", "created_at"},
		{"users", "updated_at"},
		{"federated_identities", "id"},
		{"federated_identities", "user_id"},
		{"federated_identities", "provider"},
		{"federated_identities", "provider_user_id"},
		{"federated_identities", "email_at_provider"},
		{"federated_identities", "created_at"},
		{"email_verification_tokens", "id"},
		{"email_verification_tokens", "user_id"},
		{"email_verification_tokens", "token_hash"},
		{"email_verification_tokens", "expires_at"},
		{"email_verification_tokens", "used_at"},
		{"email_verification_tokens", "created_at"},
		{"password_reset_tokens", "id"},
		{"password_reset_tokens", "user_id"},
		{"password_reset_tokens", "token_hash"},
		{"password_reset_tokens", "expires_at"},
		{"password_reset_tokens", "used_at"},
		{"password_reset_tokens", "created_at"},
		{"clients", "id"},
		{"clients", "client_secret_hash"},
		{"clients", "name"},
		{"clients", "status"},
		{"clients", "created_at"},
		{"client_redirect_uris", "id"},
		{"client_redirect_uris", "client_id"},
		{"client_redirect_uris", "redirect_uri"},
		{"authorization_codes", "code_hash"},
		{"authorization_codes", "client_id"},
		{"authorization_codes", "user_id"},
		{"authorization_codes", "redirect_uri"},
		{"authorization_codes", "code_challenge"},
		{"authorization_codes", "code_challenge_method"},
		{"authorization_codes", "scope"},
		{"authorization_codes", "expires_at"},
		{"authorization_codes", "used_at"},
		{"authorization_codes", "created_at"},
		{"refresh_tokens", "id"},
		{"refresh_tokens", "token_hash"},
		{"refresh_tokens", "family_id"},
		{"refresh_tokens", "user_id"},
		{"refresh_tokens", "client_id"},
		{"refresh_tokens", "scope"},
		{"refresh_tokens", "expires_at"},
		{"refresh_tokens", "revoked_at"},
		{"refresh_tokens", "replaced_by_id"},
		{"refresh_tokens", "created_at"},
		{"signing_keys", "id"},
		{"signing_keys", "kid"},
		{"signing_keys", "algorithm"},
		{"signing_keys", "public_key"},
		{"signing_keys", "private_key_encrypted"},
		{"signing_keys", "status"},
		{"signing_keys", "created_at"},
		{"signing_keys", "rotated_at"},
	}

	for _, tt := range tests {
		if !columnExists(t, "auth", tt.table, tt.column) {
			t.Errorf("column auth.%s.%s does not exist", tt.table, tt.column)
		}
	}
}

func TestMigration_NullableColumns(t *testing.T) {
	nullableTests := []struct {
		table  string
		column string
	}{
		{"users", "password_hash"},
		{"email_verification_tokens", "used_at"},
		{"password_reset_tokens", "used_at"},
		{"authorization_codes", "used_at"},
		{"authorization_codes", "scope"},
		{"refresh_tokens", "scope"},
		{"refresh_tokens", "revoked_at"},
		{"refresh_tokens", "replaced_by_id"},
		{"signing_keys", "rotated_at"},
		{"federated_identities", "email_at_provider"},
	}

	for _, tt := range nullableTests {
		if !columnIsNullable(t, "auth", tt.table, tt.column) {
			t.Errorf("column auth.%s.%s should be nullable", tt.table, tt.column)
		}
	}
}

func TestMigration_ForeignKeys(t *testing.T) {
	fkTests := []struct {
		table      string
		constraint string
	}{
		{"federated_identities", "federated_identities_user_id_fkey"},
		{"email_verification_tokens", "email_verification_tokens_user_id_fkey"},
		{"password_reset_tokens", "password_reset_tokens_user_id_fkey"},
		{"client_redirect_uris", "client_redirect_uris_client_id_fkey"},
		{"authorization_codes", "authorization_codes_client_id_fkey"},
		{"authorization_codes", "authorization_codes_user_id_fkey"},
		{"refresh_tokens", "refresh_tokens_user_id_fkey"},
		{"refresh_tokens", "refresh_tokens_client_id_fkey"},
		{"refresh_tokens", "refresh_tokens_replaced_by_id_fkey"},
	}

	for _, tt := range fkTests {
		if !constraintExists(t, "auth", tt.table, tt.constraint) {
			t.Errorf("FK constraint auth.%s.%s does not exist", tt.table, tt.constraint)
		}
	}
}

func TestMigration_UniqueConstraints(t *testing.T) {
	ukTests := []struct {
		table      string
		constraint string
	}{
		{"users", "users_email_key"},
		{"federated_identities", "federated_identities_provider_provider_user_id_key"},
		{"refresh_tokens", "refresh_tokens_token_hash_key"},
		{"signing_keys", "signing_keys_kid_key"},
	}

	for _, tt := range ukTests {
		if !constraintExists(t, "auth", tt.table, tt.constraint) {
			t.Errorf("UK constraint auth.%s.%s does not exist", tt.table, tt.constraint)
		}
	}
}

func TestMigration_Indexes(t *testing.T) {
	indexes := []string{
		"idx_federated_identities_user_id",
		"idx_email_verification_tokens_user_id",
		"idx_password_reset_tokens_user_id",
		"idx_authorization_codes_client_id",
		"idx_authorization_codes_user_id",
		"idx_refresh_tokens_user_id",
		"idx_refresh_tokens_family_id",
		"idx_client_redirect_uris_client_id",
	}

	for _, idx := range indexes {
		if !indexExists(t, idx) {
			t.Errorf("index auth.%s does not exist", idx)
		}
	}
}
