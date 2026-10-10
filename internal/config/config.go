package config

import (
	"os"
	"strings"
)

type Config struct {
	DatabaseURL  string
	RedisURL     string
	ServerPort   string
	CookieDomain string
	Env          string // APP_ENV: "dev" or "prod"; prod fail-fasts on weak secrets
	AdminToken   string // X-Admin-Token for /admin/* routes

	EmailDriver string // log | smtp (default log)
	SMTPHost    string
	SMTPPort    string
	SMTPUser    string
	SMTPPass    string
	EmailFrom   string
	PublicURL   string // absolute base URL used in email links

	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURI  string

	GitHubClientID     string
	GitHubClientSecret string
	GitHubRedirectURI  string

	JWTSigningKeyPath string
	JWTKID            string

	KeyEncryptionKey string // hex-encoded 32-byte key for encrypting private keys at rest
}

func Load() *Config {
	loadDotEnv()
	return &Config{
		DatabaseURL:  getenv("DATABASE_URL", "postgres://auth:auth@localhost:5435/auth?sslmode=disable"),
		RedisURL:     getenv("REDIS_URL", "redis://localhost:6380/0"),
		ServerPort:   getenv("SERVER_PORT", "8080"),
		CookieDomain: getenv("COOKIE_DOMAIN", "auth.yourdomain.com"),
		Env:          getenv("APP_ENV", "dev"),
		AdminToken:   os.Getenv("ADMIN_TOKEN"),

		EmailDriver: getenv("EMAIL_DRIVER", "log"),
		SMTPHost:    os.Getenv("SMTP_HOST"),
		SMTPPort:    os.Getenv("SMTP_PORT"),
		SMTPUser:    os.Getenv("SMTP_USER"),
		SMTPPass:    os.Getenv("SMTP_PASSWORD"),
		EmailFrom:   os.Getenv("EMAIL_FROM"),
		PublicURL:   os.Getenv("PUBLIC_URL"),

		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		GoogleRedirectURI:  getenv("GOOGLE_REDIRECT_URI", "http://localhost:8080/oauth/google/callback"),

		GitHubClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		GitHubClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		GitHubRedirectURI:  getenv("GITHUB_REDIRECT_URI", "http://localhost:8080/oauth/github/callback"),

		JWTSigningKeyPath: getenv("JWT_SIGNING_KEY_PATH", "./keys/signing.key"),
		JWTKID:            getenv("JWT_KID", "key-1"),

		KeyEncryptionKey: os.Getenv("KEY_ENCRYPTION_KEY"),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// devPlaceholders are values shipped in .env.example / dev fallbacks that
// must never reach prod (spec 4.4).
var devPlaceholders = []string{
	"fosite-dev-secret-replace-in-prod-32bytes!!",
	"auth.yourdomain.com",
	"no-reply@yourdomain.com",
}

// devKeyEncryptionKey is the hardcoded dev fallback in cmd/server (spec 4.4).
const devKeyEncryptionKey = "0000000000000000000000000000000000000000000000000000000000000001"

// Validate enforces prod secret hygiene (spec 4.4, AC-4-2). Returns a list of
// problems; empty means OK. Only APP_ENV=prod is gated — dev keeps its
// fallbacks so `cp .env.example .env && just dev` keeps working.
func (c *Config) Validate() []string {
	if c.Env != "prod" {
		return nil
	}

	var problems []string
	bad := func(v string) bool {
		for _, p := range devPlaceholders {
			if v == p {
				return true
			}
		}
		return false
	}

	if os.Getenv("FOSITE_GLOBAL_SECRET") == "" || len(os.Getenv("FOSITE_GLOBAL_SECRET")) < 32 {
		problems = append(problems, "FOSITE_GLOBAL_SECRET must be set to at least 32 bytes")
	} else if bad(os.Getenv("FOSITE_GLOBAL_SECRET")) {
		problems = append(problems, "FOSITE_GLOBAL_SECRET is a dev placeholder")
	}

	if c.KeyEncryptionKey == "" || c.KeyEncryptionKey == devKeyEncryptionKey {
		problems = append(problems, "KEY_ENCRYPTION_KEY must be set (64 hex chars, openssl rand -hex 32)")
	} else if len(c.KeyEncryptionKey) != 64 || !isHex(c.KeyEncryptionKey) {
		problems = append(problems, "KEY_ENCRYPTION_KEY must be exactly 64 hex chars")
	}

	if c.AdminToken == "" {
		problems = append(problems, "ADMIN_TOKEN must be set in prod")
	}

	if c.CookieDomain == "" || bad(c.CookieDomain) {
		problems = append(problems, "COOKIE_DOMAIN must be set to the real auth domain")
	}

	if c.EmailDriver == "smtp" {
		if c.SMTPHost == "" {
			problems = append(problems, "EMAIL_DRIVER=smtp requires SMTP_HOST")
		}
		if c.SMTPPort == "" {
			problems = append(problems, "EMAIL_DRIVER=smtp requires SMTP_PORT")
		}
		if c.EmailFrom == "" || bad(c.EmailFrom) {
			problems = append(problems, "EMAIL_DRIVER=smtp requires a real EMAIL_FROM")
		}
	} else if c.EmailDriver != "log" {
		problems = append(problems, "EMAIL_DRIVER must be log or smtp")
	}

	// Social providers: partial config (ID without secret or vice versa) is
	// always a bug; both-empty just disables that provider.
	if (c.GoogleClientID == "") != (c.GoogleClientSecret == "") {
		problems = append(problems, "GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must be set together")
	}
	if (c.GitHubClientID == "") != (c.GitHubClientSecret == "") {
		problems = append(problems, "GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET must be set together")
	}

	return problems
}

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// loadDotEnv populates unset environment variables from ./.env (AC-3-4:
// `cp .env.example .env && just dev` must work with no shell exports).
// Real environment always wins. Missing .env file is not an error.
func loadDotEnv() {
	data, err := os.ReadFile(".env")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		if os.Getenv(key) == "" {
			_ = os.Setenv(key, val)
		}
	}
}
