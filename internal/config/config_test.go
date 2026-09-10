package config

import (
	"os"
	"testing"
)

func TestLoadConfig_Defaults(t *testing.T) {
	// Clear env to test defaults
	keys := []string{"DATABASE_URL", "REDIS_URL", "SERVER_PORT", "COOKIE_DOMAIN"}
	for _, k := range keys {
		os.Unsetenv(k)
	}

	cfg := Load()

	if cfg.ServerPort != "8080" {
		t.Errorf("default ServerPort = %q, want %q", cfg.ServerPort, "8080")
	}
	if cfg.DatabaseURL != "postgres://auth:auth@localhost:5433/auth?sslmode=disable" {
		t.Errorf("default DatabaseURL = %q, want default postgres URL", cfg.DatabaseURL)
	}
	if cfg.RedisURL != "redis://localhost:6379/0" {
		t.Errorf("default RedisURL = %q, want %q", cfg.RedisURL, "redis://localhost:6379/0")
	}
}

func TestLoadConfig_FromEnv(t *testing.T) {
	t.Setenv("SERVER_PORT", "9999")
	t.Setenv("DATABASE_URL", "postgres://test:test@localhost:5432/testdb")

	cfg := Load()

	if cfg.ServerPort != "9999" {
		t.Errorf("ServerPort = %q, want %q", cfg.ServerPort, "9999")
	}
	if cfg.DatabaseURL != "postgres://test:test@localhost:5432/testdb" {
		t.Errorf("DatabaseURL = %q, want test URL", cfg.DatabaseURL)
	}
}
