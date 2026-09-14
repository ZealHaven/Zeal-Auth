package service

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func setupSessionService(t *testing.T) (*SessionService, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return NewSessionService(rdb), mr
}

func TestSession_Create_StoresInRedis(t *testing.T) {
	svc, _ := setupSessionService(t)
	ctx := context.Background()

	sess, err := svc.Create(ctx, "user-123", "client-app")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if sess.ID == "" {
		t.Fatal("session ID is empty")
	}
	if sess.UserID != "user-123" {
		t.Errorf("UserID = %q, want user-123", sess.UserID)
	}
	if sess.ClientID != "client-app" {
		t.Errorf("ClientID = %q, want client-app", sess.ClientID)
	}

	// Verify it's in Redis
	got, err := svc.Get(ctx, sess.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("session not found in Redis after Create")
	}
	if got.UserID != "user-123" {
		t.Errorf("stored UserID = %q, want user-123", got.UserID)
	}
}

func TestSession_Create_30DayTTL(t *testing.T) {
	svc, mr := setupSessionService(t)
	ctx := context.Background()

	sess, err := svc.Create(ctx, "user-456", "client-app")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Check TTL in miniredis
	ttl := mr.TTL("session:" + sess.ID)
	// Should be ~30 days (2591999-2592001 seconds range)
	if ttl < 2591999*time.Second || ttl > 2592001*time.Second {
		t.Errorf("TTL = %v, want ~30 days", ttl)
	}
}

func TestSession_Get_ValidSession(t *testing.T) {
	svc, _ := setupSessionService(t)
	ctx := context.Background()

	sess, _ := svc.Create(ctx, "user-789", "client-app")
	got, err := svc.Get(ctx, sess.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("Get returned nil for valid session")
	}
	if got.ID != sess.ID {
		t.Errorf("ID = %q, want %q", got.ID, sess.ID)
	}
}

func TestSession_Get_ExpiredSession(t *testing.T) {
	svc, mr := setupSessionService(t)
	ctx := context.Background()

	sess, _ := svc.Create(ctx, "user-abc", "client-app")

	// Fast-forward miniredis time
	mr.FastForward(31 * 24 * time.Hour)

	got, err := svc.Get(ctx, sess.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != nil {
		t.Error("Get should return nil for expired session")
	}
}

func TestSession_Get_UnknownID(t *testing.T) {
	svc, _ := setupSessionService(t)
	ctx := context.Background()

	got, err := svc.Get(ctx, "nonexistent-id")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != nil {
		t.Error("Get should return nil for unknown ID")
	}
}

func TestSession_Delete(t *testing.T) {
	svc, _ := setupSessionService(t)
	ctx := context.Background()

	sess, _ := svc.Create(ctx, "user-def", "client-app")

	err := svc.Delete(ctx, sess.ID)
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}

	got, _ := svc.Get(ctx, sess.ID)
	if got != nil {
		t.Error("session should be gone after Delete")
	}
}

func TestSession_DeleteAllForUser(t *testing.T) {
	svc, _ := setupSessionService(t)
	ctx := context.Background()

	// Create multiple sessions for user-xyz
	s1, _ := svc.Create(ctx, "user-xyz", "client-1")
	s2, _ := svc.Create(ctx, "user-xyz", "client-2")
	// Create a session for a different user
	s3, _ := svc.Create(ctx, "user-other", "client-1")

	err := svc.DeleteAllForUser(ctx, "user-xyz")
	if err != nil {
		t.Fatalf("DeleteAllForUser: %v", err)
	}

	got1, _ := svc.Get(ctx, s1.ID)
	got2, _ := svc.Get(ctx, s2.ID)
	got3, _ := svc.Get(ctx, s3.ID)

	if got1 != nil {
		t.Error("user-xyz session 1 should be deleted")
	}
	if got2 != nil {
		t.Error("user-xyz session 2 should be deleted")
	}
	if got3 == nil {
		t.Error("user-other session should NOT be deleted")
	}
}
