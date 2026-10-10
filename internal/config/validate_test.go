package config

import (
	"os"
	"testing"
)

// prodConfig returns a Config that passes Validate() untouched.
func prodConfig() *Config {
	return &Config{
		Env:              "prod",
		KeyEncryptionKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		AdminToken:       "adm-token",
		CookieDomain:     "auth.example.com",
		EmailDriver:      "smtp",
		SMTPHost:         "smtp.example.com",
		SMTPPort:         "587",
		EmailFrom:        "no-reply@example.com",
	}
}

func setEnv(t *testing.T, key, val string) {
	t.Helper()
	t.Setenv(key, val)
}

func TestValidate_DevSkipsChecks(t *testing.T) {
	c := &Config{Env: "dev"}
	if problems := c.Validate(); len(problems) != 0 {
		t.Fatalf("dev should not be gated, got %v", problems)
	}
}

func TestValidate_ProdOK(t *testing.T) {
	setEnv(t, "FOSITE_GLOBAL_SECRET", "sixteen-byte-secret-please-ok-32b")
	if problems := prodConfig().Validate(); len(problems) != 0 {
		t.Fatalf("expected clean config, got %v", problems)
	}
}

// AC-4-2: missing or placeholder secrets in APP_ENV=prod → listed problems.
func TestValidate_ProdMissingSecrets(t *testing.T) {
	setEnv(t, "FOSITE_GLOBAL_SECRET", "")
	c := &Config{Env: "prod"} // everything empty
	problems := c.Validate()
	if len(problems) < 4 {
		t.Fatalf("expected >=4 problems for empty prod config, got %d: %v", len(problems), problems)
	}
}

func TestValidate_ProdDevPlaceholders(t *testing.T) {
	setEnv(t, "FOSITE_GLOBAL_SECRET", "fosite-dev-secret-replace-in-prod-32bytes!!")
	c := prodConfig()
	c.KeyEncryptionKey = "0000000000000000000000000000000000000000000000000000000000000001"
	c.CookieDomain = "auth.yourdomain.com"
	c.EmailFrom = "no-reply@yourdomain.com"

	problems := c.Validate()
	want := map[string]bool{
		"FOSITE_GLOBAL_SECRET is a dev placeholder":                           false,
		"KEY_ENCRYPTION_KEY must be set (64 hex chars, openssl rand -hex 32)": false,
		"COOKIE_DOMAIN must be set to the real auth domain":                   false,
		"EMAIL_DRIVER=smtp requires a real EMAIL_FROM":                        false,
	}
	for _, p := range problems {
		if _, ok := want[p]; ok {
			want[p] = true
		}
	}
	for msg, found := range want {
		if !found {
			t.Errorf("missing expected problem %q; got %v", msg, problems)
		}
	}
}

func TestValidate_ProdKeyEncryptionKeyShape(t *testing.T) {
	setEnv(t, "FOSITE_GLOBAL_SECRET", "sixteen-byte-secret-please-ok-32b")
	c := prodConfig()
	c.KeyEncryptionKey = "xyz"
	problems := c.Validate()
	found := false
	for _, p := range problems {
		if p == "KEY_ENCRYPTION_KEY must be exactly 64 hex chars" {
			found = true
		}
	}
	if !found {
		t.Errorf("short non-hex key not rejected: %v", problems)
	}
}

func TestValidate_SocialPairing(t *testing.T) {
	setEnv(t, "FOSITE_GLOBAL_SECRET", "sixteen-byte-secret-please-ok-32b")
	c := prodConfig()
	c.GoogleClientID = "only-id"
	problems := c.Validate()
	found := false
	for _, p := range problems {
		if p == "GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must be set together" {
			found = true
		}
	}
	if !found {
		t.Errorf("partial Google config not rejected: %v", problems)
	}
}

func TestMain(m *testing.M) {
	// Validate reads FOSITE_GLOBAL_SECRET via os.Getenv; keep it out of the
	// ambient environment so tests are deterministic.
	_ = os.Unsetenv("FOSITE_GLOBAL_SECRET")
	os.Exit(m.Run())
}
