package handler

import (
	"context"
	"log"
	"net/http"
	"time"
)

// ctxKey is the private key type for request-context values.
type ctxKey int

const forwardedProtoKey ctxKey = iota

// TrustForwardedProto records X-Forwarded-Proto (set by Cloudflare Tunnel /
// any TLS-terminating proxy) so downstream code can tell the original scheme
// while the origin itself speaks plain HTTP (spec 4.3).
func TrustForwardedProto(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := r.Header.Get("X-Forwarded-Proto"); p == "https" || p == "http" {
			r = r.WithContext(context.WithValue(r.Context(), forwardedProtoKey, p))
		}
		next.ServeHTTP(w, r)
	})
}

// ForwardedProto returns the original request scheme: the proxy header when
// present, otherwise "https" for direct TLS, else "http".
func ForwardedProto(r *http.Request) string {
	if p, ok := r.Context().Value(forwardedProtoKey).(string); ok {
		return p
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// withMiddleware is the baseline stack for the bare ServeMux (spec 4.9):
// panic recovery, request logging, security headers. hsts enables the
// Strict-Transport-Security header (prod only — meaningless over plain HTTP).
func withMiddleware(next http.Handler, hsts bool) http.Handler {
	return TrustForwardedProto(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic: %s %s: %v", r.Method, r.URL.Path, rec)
				http.Error(w, "internal_error", http.StatusInternalServerError)
			}
		}()

		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		if hsts {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}

		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, sw.status, time.Since(start).Round(time.Millisecond))
	}))
}
