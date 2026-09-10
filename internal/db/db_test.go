package db

import (
	"context"
	"testing"
)

func TestNewPool_BadURL_ReturnsError(t *testing.T) {
	ctx := context.Background()
	_, err := NewPool(ctx, "postgres://invalid:invalid@nonexistent:9999/nodb")
	if err == nil {
		t.Fatal("expected error for bad DB URL, got nil")
	}
}
