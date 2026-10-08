package repository

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/zeal/auth/internal/db"
)

var testPool *pgxpool.Pool

func testDBURL() string {
	return db.TestURL()
}

func TestMain(m *testing.M) {
	ctx := context.Background()
	if err := db.EnsureTestDatabase(ctx); err != nil {
		panic("ensure test database: " + err.Error())
	}
	var err error
	testPool, err = pgxpool.New(ctx, testDBURL())
	if err != nil {
		panic("connect pool: " + err.Error())
	}

	// Run migrations (idempotent)
	_, _ = testPool.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS auth")
	var exists bool
	_ = testPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema='auth' AND table_name='users')`).Scan(&exists)
	if !exists {
		out, _ := os.ReadFile("../../migrations/000001_init.up.sql")
		if out != nil {
			_, err = testPool.Exec(ctx, string(out))
			if err != nil {
				panic("run migration: " + err.Error())
			}
		}
	}

	code := m.Run()

	testPool.Close()
	os.Exit(code)
}

func cleanUsers(t *testing.T) {
	t.Helper()
	_, err := testPool.Exec(context.Background(), "DELETE FROM auth.users")
	if err != nil {
		t.Fatalf("clean users: %v", err)
	}
}

func TestUserRepo_Create_Success(t *testing.T) {
	cleanUsers(t)
	ctx := context.Background()
	repo := NewUserRepository(testPool)

	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	user, err := repo.Create(ctx, "test@example.com", string(hash))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if user.Email != "test@example.com" {
		t.Errorf("Email = %q, want %q", user.Email, "test@example.com")
	}
	if user.PasswordHash == nil {
		t.Error("PasswordHash is nil")
	}
	if user.EmailVerified {
		t.Error("EmailVerified should be false for new user")
	}
	if user.ID == uuid.Nil {
		t.Error("ID should not be nil")
	}
}

func TestUserRepo_Create_DuplicateEmail(t *testing.T) {
	cleanUsers(t)
	ctx := context.Background()
	repo := NewUserRepository(testPool)

	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	_, err := repo.Create(ctx, "dup@example.com", string(hash))
	if err != nil {
		t.Fatalf("first Create: %v", err)
	}

	_, err = repo.Create(ctx, "dup@example.com", string(hash))
	if err != ErrDuplicateEmail {
		t.Errorf("expected ErrDuplicateEmail, got %v", err)
	}
}

func TestUserRepo_GetByEmail_Found(t *testing.T) {
	cleanUsers(t)
	ctx := context.Background()
	repo := NewUserRepository(testPool)

	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	created, _ := repo.Create(ctx, "find@example.com", string(hash))

	found, err := repo.GetByEmail(ctx, "find@example.com")
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if found.ID != created.ID {
		t.Errorf("ID = %v, want %v", found.ID, created.ID)
	}
}

func TestUserRepo_GetByEmail_NotFound(t *testing.T) {
	cleanUsers(t)
	ctx := context.Background()
	repo := NewUserRepository(testPool)

	_, err := repo.GetByEmail(ctx, "missing@example.com")
	if err != ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
}

func TestUserRepo_GetByID_Found(t *testing.T) {
	cleanUsers(t)
	ctx := context.Background()
	repo := NewUserRepository(testPool)

	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	created, _ := repo.Create(ctx, "byid@example.com", string(hash))

	found, err := repo.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if found.Email != "byid@example.com" {
		t.Errorf("Email = %q, want %q", found.Email, "byid@example.com")
	}
}

func TestUserRepo_MarkEmailVerified(t *testing.T) {
	cleanUsers(t)
	ctx := context.Background()
	repo := NewUserRepository(testPool)

	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	user, _ := repo.Create(ctx, "verify@example.com", string(hash))

	if user.EmailVerified {
		t.Fatal("should start unverified")
	}

	err := repo.MarkEmailVerified(ctx, user.ID)
	if err != nil {
		t.Fatalf("MarkEmailVerified: %v", err)
	}

	verified, _ := repo.GetByID(ctx, user.ID)
	if !verified.EmailVerified {
		t.Error("EmailVerified should be true after marking")
	}
}
