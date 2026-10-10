package service

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RateLimiter implements brute-force throttling on Redis counters (spec 4.5,
// AC-4-3): fixed window per key, with lockout backoff — every failed attempt
// while already locked doubles the remaining window (capped at maxBackoff).
type RateLimiter struct {
	rdb        *redis.Client
	maxBackoff time.Duration
}

func NewRateLimiter(rdb *redis.Client) *RateLimiter {
	return &RateLimiter{rdb: rdb, maxBackoff: time.Hour}
}

const ratePrefix = "rl:"

func rateKey(scope, id string) string { return ratePrefix + scope + ":" + id }

// Check reports whether id has already hit limit within window (does not
// count the current attempt). Returns remaining lockout time when blocked.
func (l *RateLimiter) Check(ctx context.Context, scope, id string, limit int) (blocked bool, retryAfter time.Duration, err error) {
	key := rateKey(scope, id)
	n, err := l.rdb.Get(ctx, key).Int()
	if err == redis.Nil {
		return false, 0, nil
	}
	if err != nil {
		return false, 0, fmt.Errorf("rate check: %w", err)
	}
	if n < limit {
		return false, 0, nil
	}
	ttl, err := l.rdb.TTL(ctx, key).Result()
	if err != nil {
		return false, 0, fmt.Errorf("rate ttl: %w", err)
	}
	return true, ttl, nil
}

// Hit records one attempt. When the key reaches limit the window becomes a
// lockout; attempts made while locked double the remaining window — capped at
// maxBackoff — so repeated guessing extends the lockout (spec 4.5 backoff).
// Returns the key's current count.
func (l *RateLimiter) Hit(ctx context.Context, scope, id string, limit int, window time.Duration) (int, error) {
	key := rateKey(scope, id)
	n, err := l.rdb.Incr(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("rate hit: %w", err)
	}
	if n == 1 {
		if err := l.rdb.Expire(ctx, key, window).Err(); err != nil {
			return int(n), fmt.Errorf("rate expire: %w", err)
		}
		return int(n), nil
	}
	if int(n) > limit {
		ttl, err := l.rdb.TTL(ctx, key).Result()
		if err == nil && ttl > 0 {
			next := ttl * 2
			if next > l.maxBackoff {
				next = l.maxBackoff
			}
			if next > ttl {
				_ = l.rdb.Expire(ctx, key, next).Err()
			}
		}
	}
	return int(n), nil
}

// Reset clears a counter — called after a successful login so a legitimate
// user's past failures don't count against them (AC-4-3).
func (l *RateLimiter) Reset(ctx context.Context, scope, id string) error {
	return l.rdb.Del(ctx, rateKey(scope, id)).Err()
}
