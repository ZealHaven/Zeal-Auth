package config

import "os"

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
	return &Config{
		DatabaseURL:  getenv("DATABASE_URL", "postgres://auth:auth@localhost:5435/auth?sslmode=disable"),
		RedisURL:     getenv("REDIS_URL", "redis://localhost:6379/0"),
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
