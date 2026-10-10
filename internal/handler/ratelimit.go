package handler

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zeal/auth/internal/service"
)

// Rate-limit policy (spec 4.5, AC-4-3): 6 failures per 10 minutes locks the
// account and the client IP; window then applies as the minimum lockout.
const (
	loginLimit    = 6
	loginWindow   = 10 * time.Minute
	generalLimit  = 20 // signup/reset: more generous than login
	generalWindow = 10 * time.Minute
	tokenLimit    = 60 // /token: clients poll legitimately; still bounds floods
	tokenWindow   = time.Minute
)

// clientIP extracts the caller IP: first X-Forwarded-For entry when behind
// the tunnel/proxy, else the socket address.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if ip, _, ok := strings.Cut(xff, ","); ok {
			return strings.TrimSpace(ip)
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// rateBlocked checks the limiter for the given scopes; returns retry-after
// seconds when one is exhausted.
func rateBlocked(ctx context.Context, l *service.RateLimiter, r *http.Request, scope, id string, limit int) (int, bool) {
	if l == nil {
		return 0, false
	}
	for _, key := range []string{clientIP(r), id} {
		if key == "" {
			continue
		}
		blocked, retry, err := l.Check(ctx, scope, key, limit)
		if err != nil || !blocked {
			continue
		}
		secs := int(retry.Seconds()) + 1
		return secs, true
	}
	return 0, false
}

// rateHit records one attempt against IP and id.
func rateHit(ctx context.Context, l *service.RateLimiter, r *http.Request, scope, id string, limit int, window time.Duration) {
	if l == nil {
		return
	}
	for _, key := range []string{clientIP(r), id} {
		if key == "" {
			continue
		}
		_, _ = l.Hit(ctx, scope, key, limit, window)
	}
}

// rateReset clears the account counter after a successful auth.
func rateReset(ctx context.Context, l *service.RateLimiter, scope, id string) {
	if l == nil || id == "" {
		return
	}
	_ = l.Reset(ctx, scope, id)
}

// rateIPMiddleware throttles a whole endpoint per client IP (spec 4.5 —
// used on POST /token, where there is no account key until auth succeeds).
func rateIPMiddleware(l *service.RateLimiter, scope string, limit int, window time.Duration, next http.HandlerFunc) http.HandlerFunc {
	if l == nil {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if secs, ok := rateBlocked(r.Context(), l, r, scope, clientIP(r), limit); ok {
			writeRateLimited(w, secs)
			return
		}
		rateHit(r.Context(), l, r, scope, clientIP(r), limit, window)
		next(w, r)
	}
}

func writeRateLimited(w http.ResponseWriter, retrySecs int) {
	w.Header().Set("Retry-After", strconv.Itoa(retrySecs))
	writeError(w, http.StatusTooManyRequests, "rate_limited")
}

// writeHTMLRateLimited is the form-path variant: 429 + Retry-After, body still
// rendered by the caller as HTML.
func writeHTMLRateLimited(w http.ResponseWriter, retrySecs int) {
	w.Header().Set("Retry-After", strconv.Itoa(retrySecs))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusTooManyRequests)
}
