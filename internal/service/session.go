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
