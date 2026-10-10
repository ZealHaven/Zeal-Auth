package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zeal/auth/internal/db"
)

func testDBURL() string {
	return db.TestURL()
}

const testEncKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()
	db.SkipIfNoPostgres(ctx)
	var err error
	testPool, err = pgxpool.New(ctx, testDBURL())
	if err != nil {
		panic("connect pool: " + err.Error())
	}

	// Run migrations
	_, _ = testPool.Exec(ctx, "DROP SCHEMA IF EXISTS auth CASCADE")
	_, _ = testPool.Exec(ctx, "DROP TABLE IF EXISTS public.schema_migrations")
	// ensure schema exists
	_, _ = testPool.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS auth")
	// run migrations up via the SQL files
	for _, f := range []string{"../../migrations/000001_init.up.sql", "../../migrations/000002_oauth2_storage.up.sql",
		"../../migrations/000003_productization.up.sql", "../../migrations/000004_scope_grants.up.sql",
		"../../migrations/000005_client_scopes.up.sql"} {
		out, _ := os.ReadFile(f)
		if out != nil {
			if _, err = testPool.Exec(ctx, string(out)); err != nil {
				panic("run migration " + f + ": " + err.Error())
			}
		}
	}

	code := m.Run()

	_, _ = testPool.Exec(ctx, "DROP SCHEMA IF EXISTS auth CASCADE")
	_, _ = testPool.Exec(ctx, "DROP TABLE IF EXISTS public.schema_migrations")
	testPool.Close()
	os.Exit(code)
}

func cleanSigningKeys(t *testing.T) {
	t.Helper()
	_, err := testPool.Exec(context.Background(), "DELETE FROM auth.signing_keys")
	if err != nil {
		t.Fatalf("clean signing_keys: %v", err)
	}
}

func TestGenerateKeyPair_ReturnsRSA2048(t *testing.T) {
	cleanSigningKeys(t)
	ctx := context.Background()

	kp, err := GenerateKeyPair(ctx, testPool, "test-key-1", testEncKeyHex)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Parse the private key to verify it's RSA 2048
	block, _ := pem.Decode(kp.PrivateKeyPEM)
	if block == nil {
		t.Fatal("failed to decode private key PEM")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}
	if priv.N.BitLen() != 2048 {
		t.Errorf("key bit length = %d, want 2048", priv.N.BitLen())
	}

	// Parse public key PEM
	pubBlock, _ := pem.Decode(kp.PublicKeyPEM)
	if pubBlock == nil {
		t.Fatal("failed to decode public key PEM")
	}
	if pubBlock.Type != "PUBLIC KEY" {
		t.Errorf("public key block type = %q, want %q", pubBlock.Type, "PUBLIC KEY")
	}
}

func TestEncryptDecrypt_Roundtrip(t *testing.T) {
	encKey, _ := hex.DecodeString(testEncKeyHex)

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	enc, err := EncryptPrivateKey(privPEM, encKey)
	if err != nil {
		t.Fatalf("EncryptPrivateKey: %v", err)
	}

	dec, err := DecryptPrivateKey(enc, encKey)
	if err != nil {
		t.Fatalf("DecryptPrivateKey: %v", err)
	}

	if string(dec) != string(privPEM) {
		t.Error("decrypted key does not match original")
	}
}

func TestEncryptDecrypt_WrongKey_Fails(t *testing.T) {
	key1, _ := hex.DecodeString(testEncKeyHex)
	key2 := make([]byte, 32)
	for i := range key2 {
		key2[i] = 0xff
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	enc, err := EncryptPrivateKey(privPEM, key1)
	if err != nil {
		t.Fatalf("EncryptPrivateKey: %v", err)
	}

	_, err = DecryptPrivateKey(enc, key2)
	if err == nil {
		t.Error("expected error decrypting with wrong key, got nil")
	}
}

func TestEnsureInitialKey_CreatesOnFreshDB(t *testing.T) {
	cleanSigningKeys(t)
	ctx := context.Background()

	err := EnsureInitialKey(ctx, testPool, "key-1", testEncKeyHex)
	if err != nil {
		t.Fatalf("EnsureInitialKey: %v", err)
	}

	var count int
	err = testPool.QueryRow(ctx, "SELECT count(*) FROM auth.signing_keys").Scan(&count)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 key, got %d", count)
	}
}

func TestEnsureInitialKey_NoopIfExists(t *testing.T) {
	cleanSigningKeys(t)
	ctx := context.Background()

	err := EnsureInitialKey(ctx, testPool, "key-1", testEncKeyHex)
	if err != nil {
		t.Fatalf("EnsureInitialKey (first): %v", err)
	}

	err = EnsureInitialKey(ctx, testPool, "key-1", testEncKeyHex)
	if err != nil {
		t.Fatalf("EnsureInitialKey (second): %v", err)
	}

	var count int
	err = testPool.QueryRow(ctx, "SELECT count(*) FROM auth.signing_keys").Scan(&count)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 key after second EnsureInitialKey, got %d", count)
	}
}

func TestGetActiveKey_ReturnsDecryptableKey(t *testing.T) {
	cleanSigningKeys(t)
	ctx := context.Background()

	_, err := GenerateKeyPair(ctx, testPool, "key-1", testEncKeyHex)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	kp, err := GetActiveKey(ctx, testPool, testEncKeyHex)
	if err != nil {
		t.Fatalf("GetActiveKey: %v", err)
	}

	// Verify we can parse the decrypted private key
	block, _ := pem.Decode(kp.PrivateKeyPEM)
	if block == nil {
		t.Fatal("failed to decode private key PEM from GetActiveKey")
	}
	_, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse decrypted private key: %v", err)
	}

	if kp.KID != "key-1" {
		t.Errorf("KID = %q, want %q", kp.KID, "key-1")
	}
	if kp.Status != "active" {
		t.Errorf("Status = %q, want %q", kp.Status, "active")
	}
}

func TestGetAllActiveKeys_IncludesActiveAndRetiring(t *testing.T) {
	cleanSigningKeys(t)
	ctx := context.Background()

	encKey, _ := hex.DecodeString(testEncKeyHex)

	// Create a retiring key manually
	priv1, _ := rsa.GenerateKey(rand.Reader, 2048)
	priv1PEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv1)})
	pub1Bytes, _ := x509.MarshalPKIXPublicKey(&priv1.PublicKey)
	pub1PEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub1Bytes})
	enc1, _ := EncryptPrivateKey(priv1PEM, encKey)

	_, err := testPool.Exec(ctx,
		`INSERT INTO auth.signing_keys (kid, algorithm, public_key, private_key_encrypted, status)
		 VALUES ('retiring-key', 'RS256', $1, $2, 'retiring')`,
		string(pub1PEM), base64.StdEncoding.EncodeToString(enc1),
	)
	if err != nil {
		t.Fatalf("insert retiring key: %v", err)
	}

	// Create an active key
	_, err = GenerateKeyPair(ctx, testPool, "active-key", testEncKeyHex)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	keys, err := GetAllActiveKeys(ctx, testPool, testEncKeyHex)
	if err != nil {
		t.Fatalf("GetAllActiveKeys: %v", err)
	}

	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}

	hasRetiring := false
	hasActive := false
	for _, k := range keys {
		if k.Status == "retiring" {
			hasRetiring = true
		}
		if k.Status == "active" {
			hasActive = true
		}
	}
	if !hasRetiring {
		t.Error("missing retiring key")
	}
	if !hasActive {
		t.Error("missing active key")
	}
}

func TestRotateKey_DemotesOld_CreatesNew(t *testing.T) {
	cleanSigningKeys(t)
	ctx := context.Background()

	// Create initial key
	_, err := GenerateKeyPair(ctx, testPool, "key-1", testEncKeyHex)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Rotate
	newKey, err := RotateKey(ctx, testPool, "key-2", testEncKeyHex)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	if newKey.KID != "key-2" {
		t.Errorf("new key KID = %q, want %q", newKey.KID, "key-2")
	}

	// Check old key is retiring
	var oldStatus string
	err = testPool.QueryRow(ctx,
		`SELECT status FROM auth.signing_keys WHERE kid = 'key-1'`,
	).Scan(&oldStatus)
	if err != nil {
		t.Fatalf("query old key: %v", err)
	}
	if oldStatus != "retiring" {
		t.Errorf("old key status = %q, want %q", oldStatus, "retiring")
	}

	// Check new key is active
	var newStatus string
	err = testPool.QueryRow(ctx,
		`SELECT status FROM auth.signing_keys WHERE kid = 'key-2'`,
	).Scan(&newStatus)
	if err != nil {
		t.Fatalf("query new key: %v", err)
	}
	if newStatus != "active" {
		t.Errorf("new key status = %q, want %q", newStatus, "active")
	}
}

func TestRetireOldKeys_MarksRetired(t *testing.T) {
	cleanSigningKeys(t)
	ctx := context.Background()

	encKey, _ := hex.DecodeString(testEncKeyHex)

	// Create a retiring key with rotated_at = 2 hours ago
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	pubBytes, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	encPriv, _ := EncryptPrivateKey(privPEM, encKey)

	_, err := testPool.Exec(ctx,
		`INSERT INTO auth.signing_keys (kid, algorithm, public_key, private_key_encrypted, status, rotated_at)
		 VALUES ('old-key', 'RS256', $1, $2, 'retiring', now() - interval '2 hours')`,
		string(pubPEM), base64.StdEncoding.EncodeToString(encPriv),
	)
	if err != nil {
		t.Fatalf("insert old retiring key: %v", err)
	}

	// Create a recent retiring key (10 min ago) — should NOT be retired
	priv2, _ := rsa.GenerateKey(rand.Reader, 2048)
	priv2PEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv2)})
	pub2Bytes, _ := x509.MarshalPKIXPublicKey(&priv2.PublicKey)
	pub2PEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub2Bytes})
	enc2, _ := EncryptPrivateKey(priv2PEM, encKey)

	_, err = testPool.Exec(ctx,
		`INSERT INTO auth.signing_keys (kid, algorithm, public_key, private_key_encrypted, status, rotated_at)
		 VALUES ('recent-key', 'RS256', $1, $2, 'retiring', now() - interval '10 minutes')`,
		string(pub2PEM), base64.StdEncoding.EncodeToString(enc2),
	)
	if err != nil {
		t.Fatalf("insert recent retiring key: %v", err)
	}

	affected, err := RetireOldKeys(ctx, testPool, 1*time.Hour)
	if err != nil {
		t.Fatalf("RetireOldKeys: %v", err)
	}

	if affected != 1 {
		t.Errorf("expected 1 retired key, got %d", affected)
	}

	// Verify old key is retired
	var status string
	err = testPool.QueryRow(ctx,
		`SELECT status FROM auth.signing_keys WHERE kid = 'old-key'`,
	).Scan(&status)
	if err != nil {
		t.Fatalf("query old key: %v", err)
	}
	if status != "retired" {
		t.Errorf("old key status = %q, want %q", status, "retired")
	}

	// Verify recent key is still retiring
	err = testPool.QueryRow(ctx,
		`SELECT status FROM auth.signing_keys WHERE kid = 'recent-key'`,
	).Scan(&status)
	if err != nil {
		t.Fatalf("query recent key: %v", err)
	}
	if status != "retiring" {
		t.Errorf("recent key status = %q, want %q", status, "retiring")
	}
}

func TestPrivateKey_NeverStoredPlaintext(t *testing.T) {
	cleanSigningKeys(t)
	ctx := context.Background()

	_, err := GenerateKeyPair(ctx, testPool, "key-1", testEncKeyHex)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	var stored string
	err = testPool.QueryRow(ctx,
		`SELECT private_key_encrypted FROM auth.signing_keys WHERE kid = 'key-1'`,
	).Scan(&stored)
	if err != nil {
		t.Fatalf("query: %v", err)
	}

	// PEM-encoded RSA private keys always start with "-----BEGIN RSA PRIVATE KEY-----"
	if strings.HasPrefix(stored, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Error("private key stored as plaintext")
	}
}
