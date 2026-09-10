package service

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type KeyPair struct {
	ID            string
	KID           string
	PublicKeyPEM  []byte
	PrivateKeyPEM []byte // decrypted; never stored in DB
	Status        string
	CreatedAt     time.Time
}

// GenerateKeyPair generates a new RSA 2048-bit key pair and returns PEM-encoded
// public key and encrypted private key.
func GenerateKeyPair(ctx context.Context, pool *pgxpool.Pool, kid string, encKeyHex string) (*KeyPair, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	encKey, err := hex.DecodeString(encKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decode encryption key: %w", err)
	}

	encPriv, err := EncryptPrivateKey(privPEM, encKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt private key: %w", err)
	}

	var id string
	err = pool.QueryRow(ctx,
		`INSERT INTO auth.signing_keys (kid, algorithm, public_key, private_key_encrypted, status)
		 VALUES ($1, 'RS256', $2, $3, 'active')
		 RETURNING id`,
		kid, string(pubPEM), base64.StdEncoding.EncodeToString(encPriv),
	).Scan(&id)
	if err != nil {
		return nil, fmt.Errorf("insert signing key: %w", err)
	}

	return &KeyPair{
		ID:            id,
		KID:           kid,
		PublicKeyPEM:  pubPEM,
		PrivateKeyPEM: privPEM,
		Status:        "active",
		CreatedAt:     time.Now(),
	}, nil
}

// GetActiveKey returns the active signing key with its private key decrypted.
func GetActiveKey(ctx context.Context, pool *pgxpool.Pool, encKeyHex string) (*KeyPair, error) {
	encKey, err := hex.DecodeString(encKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decode encryption key: %w", err)
	}

	var id, kid, status string
	var pubPEM, encPrivPEM string
	var createdAt time.Time
	err = pool.QueryRow(ctx,
		`SELECT id, kid, public_key, private_key_encrypted, status, created_at
		 FROM auth.signing_keys
		 WHERE status = 'active'
		 ORDER BY created_at DESC LIMIT 1`,
	).Scan(&id, &kid, &pubPEM, &encPrivPEM, &status, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("get active key: %w", err)
	}

	encPrivBytes, err := base64.StdEncoding.DecodeString(encPrivPEM)
	if err != nil {
		return nil, fmt.Errorf("base64 decode private key: %w", err)
	}

	privPEM, err := DecryptPrivateKey(encPrivBytes, encKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt private key: %w", err)
	}

	return &KeyPair{
		ID:            id,
		KID:           kid,
		PublicKeyPEM:  []byte(pubPEM),
		PrivateKeyPEM: privPEM,
		Status:        status,
		CreatedAt:     createdAt,
	}, nil
}

// GetAllActiveKeys returns all keys with status active or retiring (for JWKS endpoint).
func GetAllActiveKeys(ctx context.Context, pool *pgxpool.Pool, encKeyHex string) ([]*KeyPair, error) {
	encKey, err := hex.DecodeString(encKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decode encryption key: %w", err)
	}

	rows, err := pool.Query(ctx,
		`SELECT id, kid, public_key, private_key_encrypted, status, created_at
		 FROM auth.signing_keys
		 WHERE status IN ('active', 'retiring')
		 ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("query signing keys: %w", err)
	}
	defer rows.Close()

	var keys []*KeyPair
	for rows.Next() {
		var id, kid, status string
		var pubPEM, encPrivPEM string
		var createdAt time.Time
		if err := rows.Scan(&id, &kid, &pubPEM, &encPrivPEM, &status, &createdAt); err != nil {
			return nil, fmt.Errorf("scan signing key: %w", err)
		}

		encPrivBytes, err := base64.StdEncoding.DecodeString(encPrivPEM)
		if err != nil {
			return nil, fmt.Errorf("base64 decode key %s: %w", kid, err)
		}

		privPEM, err := DecryptPrivateKey(encPrivBytes, encKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt key %s: %w", kid, err)
		}

		keys = append(keys, &KeyPair{
			ID:            id,
			KID:           kid,
			PublicKeyPEM:  []byte(pubPEM),
			PrivateKeyPEM: privPEM,
			Status:        status,
			CreatedAt:     createdAt,
		})
	}
	return keys, rows.Err()
}

// RotateKey demotes the current active key to retiring and generates a new active key.
func RotateKey(ctx context.Context, pool *pgxpool.Pool, kid string, encKeyHex string) (*KeyPair, error) {
	// Demote current active key
	_, err := pool.Exec(ctx,
		`UPDATE auth.signing_keys SET status = 'retiring', rotated_at = now()
		 WHERE status = 'active'`,
	)
	if err != nil {
		return nil, fmt.Errorf("demote active key: %w", err)
	}

	// Generate new active key
	return GenerateKeyPair(ctx, pool, kid, encKeyHex)
}

// RetireOldKeys marks retiring keys older than the rotation window as retired.
// rotationWindow is how long a retiring key stays available (e.g. 24h).
func RetireOldKeys(ctx context.Context, pool *pgxpool.Pool, rotationWindow time.Duration) (int64, error) {
	tag, err := pool.Exec(ctx,
		`UPDATE auth.signing_keys SET status = 'retired'
		 WHERE status = 'retiring' AND rotated_at < now() - $1::interval`,
		rotationWindow.String(),
	)
	if err != nil {
		return 0, fmt.Errorf("retire old keys: %w", err)
	}
	return tag.RowsAffected(), nil
}

// EnsureInitialKey generates a key pair if none exists in the database.
func EnsureInitialKey(ctx context.Context, pool *pgxpool.Pool, kid string, encKeyHex string) error {
	var count int
	err := pool.QueryRow(ctx,
		`SELECT count(*) FROM auth.signing_keys`,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("count signing keys: %w", err)
	}
	if count > 0 {
		return nil
	}

	_, err = GenerateKeyPair(ctx, pool, kid, encKeyHex)
	if err != nil {
		return fmt.Errorf("generate initial key: %w", err)
	}
	return nil
}

// EncryptPrivateKey encrypts a PEM-encoded private key using AES-GCM.
func EncryptPrivateKey(privPEM []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := aesGCM.Seal(nonce, nonce, privPEM, nil)
	return ciphertext, nil
}

// DecryptPrivateKey decrypts an AES-GCM encrypted private key back to PEM.
func DecryptPrivateKey(encPEM []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(encPEM) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := encPEM[:nonceSize], encPEM[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// ParseRSAPrivateKey parses a PEM-encoded RSA private key for use with JWT signing.
func ParseRSAPrivateKey(privPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
