package config

import "os"

type Config struct {
	DatabaseURL  string
	RedisURL     string
	ServerPort   string
	CookieDomain string

	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURI  string

	GitHubClientID     string
	GitHubClientSecret string
	GitHubRedirectURI  string

	JWTSigningKeyPath string
	JWTKID            string
}

func Load() *Config {
	return &Config{
		DatabaseURL:  getenv("DATABASE_URL", "postgres://auth:auth@localhost:5433/auth?sslmode=disable"),
		RedisURL:     getenv("REDIS_URL", "redis://localhost:6379/0"),
		ServerPort:   getenv("SERVER_PORT", "8080"),
		CookieDomain: getenv("COOKIE_DOMAIN", "auth.yourdomain.com"),

		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		GoogleRedirectURI:  getenv("GOOGLE_REDIRECT_URI", "http://localhost:8080/oauth/google/callback"),

		GitHubClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		GitHubClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		GitHubRedirectURI:  getenv("GITHUB_REDIRECT_URI", "http://localhost:8080/oauth/github/callback"),

		JWTSigningKeyPath: getenv("JWT_SIGNING_KEY_PATH", "./keys/signing.key"),
		JWTKID:            getenv("JWT_KID", "key-1"),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
