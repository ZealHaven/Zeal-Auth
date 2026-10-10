package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	SessionCookieName = "sid"
	CookiePath        = "/"
	CookieMaxAge      = 30 * 24 * 3600 // 30 days in seconds
)

type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type SessionService struct {
	rdb *redis.Client
	ttl time.Duration
}

func NewSessionService(rdb *redis.Client) *SessionService {
	return &SessionService{
		rdb: rdb,
		ttl: 30 * 24 * time.Hour, // 30 days
	}
}

func (s *SessionService) Create(ctx context.Context, userID string, clientID string) (*Session, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate session id: %w", err)
	}

	sess := &Session{
		ID:        hex.EncodeToString(b),
		UserID:    userID,
		ClientID:  clientID,
		ExpiresAt: time.Now().Add(s.ttl),
	}

	data, err := json.Marshal(sess)
	if err != nil {
		return nil, fmt.Errorf("marshal session: %w", err)
	}

	key := "session:" + sess.ID
	if err := s.rdb.Set(ctx, key, data, s.ttl).Err(); err != nil {
		return nil, fmt.Errorf("store session: %w", err)
	}

	return sess, nil
}

func (s *SessionService) Get(ctx context.Context, sessionID string) (*Session, error) {
	key := "session:" + sessionID
	data, err := s.rdb.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, fmt.Errorf("get session: %w", err)
	}

	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}

	return &sess, nil
}

func (s *SessionService) Delete(ctx context.Context, sessionID string) error {
	key := "session:" + sessionID
	return s.rdb.Del(ctx, key).Err()
}

// ListForUser returns all active sessions for a user (spec 5.4 admin + 5.7
// self-service). Each entry includes the raw session ID so a caller can revoke
// one individually.
func (s *SessionService) ListForUser(ctx context.Context, userID string) ([]Session, error) {
	var cursor uint64
	out := []Session{}

	for {
		keys, nextCursor, err := s.rdb.Scan(ctx, cursor, "session:*", 100).Result()
		if err != nil {
			return nil, fmt.Errorf("scan sessions: %w", err)
		}
		for _, key := range keys {
			data, err := s.rdb.Get(ctx, key).Bytes()
			if err != nil {
				continue
			}
			var sess Session
			if err := json.Unmarshal(data, &sess); err != nil {
				continue
			}
			if sess.UserID == userID {
				out = append(out, sess)
			}
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return out, nil
}

// ---- MFA step-up state (spec 5.6) ----

const (
	mfaPendingTTL  = 5 * time.Minute
	mfaLastTOTPTTL = 60 * time.Second // one TOTP step + skew: blocks replay (AC-5-4)
)

// CreatePendingMFA stores a short-lived step-up challenge; returns its token.
func (s *SessionService) CreatePendingMFA(ctx context.Context, userID string) (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	if err := s.rdb.Set(ctx, "mfa:"+token, userID, mfaPendingTTL).Err(); err != nil {
		return "", fmt.Errorf("store mfa pending: %w", err)
	}
	return token, nil
}

// GetPendingMFA resolves a step-up token to its user id ("" when expired/unknown).
func (s *SessionService) GetPendingMFA(ctx context.Context, token string) string {
	v, err := s.rdb.Get(ctx, "mfa:"+token).Result()
	if err != nil {
		return ""
	}
	return v
}

// DeletePendingMFA consumes a step-up token (single-use).
func (s *SessionService) DeletePendingMFA(ctx context.Context, token string) {
	_ = s.rdb.Del(ctx, "mfa:"+token).Err()
}

// RememberTOTPCode records the last accepted TOTP code for a user so a replay
// within the validity window is rejected (AC-5-4).
func (s *SessionService) RememberTOTPCode(ctx context.Context, userID, code string) {
	_ = s.rdb.Set(ctx, "mfa:last:"+userID, code, mfaLastTOTPTTL).Err()
}

// TOTPCodeReplayed reports whether code was already accepted in this window.
func (s *SessionService) TOTPCodeReplayed(ctx context.Context, userID, code string) bool {
	last, err := s.rdb.Get(ctx, "mfa:last:"+userID).Result()
	return err == nil && last == code
}

func (s *SessionService) DeleteAllForUser(ctx context.Context, userID string) error {
	var cursor uint64
	pattern := "session:*"

	for {
		keys, nextCursor, err := s.rdb.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return fmt.Errorf("scan sessions: %w", err)
		}

		for _, key := range keys {
			data, err := s.rdb.Get(ctx, key).Bytes()
			if err != nil {
				continue
			}

			var sess Session
			if err := json.Unmarshal(data, &sess); err != nil {
				continue
			}

			if sess.UserID == userID {
				_ = s.rdb.Del(ctx, key).Err()
			}
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return nil
}

func SetSessionCookie(w http.ResponseWriter, sessionID, domain string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionID,
		Domain:   domain,
		Path:     CookiePath,
		MaxAge:   CookieMaxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func ClearSessionCookie(w http.ResponseWriter, domain string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Domain:   domain,
		Path:     CookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func GetSessionIDFromRequest(r *http.Request) string {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}
