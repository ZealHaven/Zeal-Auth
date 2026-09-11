package service

import (
	"testing"
)

func TestGenerateToken_Length(t *testing.T) {
	tok, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if len(tok) != 64 {
		t.Errorf("len = %d, want 64", len(tok))
	}
}

func TestGenerateToken_Random(t *testing.T) {
	tok1, _ := GenerateToken()
	tok2, _ := GenerateToken()
	if tok1 == tok2 {
		t.Error("two tokens should not be equal")
	}
}

func TestHashToken_Deterministic(t *testing.T) {
	tok := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	h1 := HashToken(tok)
	h2 := HashToken(tok)
	if h1 != h2 {
		t.Errorf("same input should produce same hash")
	}
}

func TestHashToken_DifferentInputs(t *testing.T) {
	h1 := HashToken("token1")
	h2 := HashToken("token2")
	if h1 == h2 {
		t.Error("different tokens should produce different hashes")
	}
}

func TestHashToken_Length(t *testing.T) {
	h := HashToken("test")
	if len(h) != 64 {
		t.Errorf("hash len = %d, want 64", len(h))
	}
}
