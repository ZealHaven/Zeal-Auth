package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// GenerateToken returns a 32-byte random hex string (64 chars).
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// HashToken returns the SHA-256 hex of the given token.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
