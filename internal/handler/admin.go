package handler

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zeal/auth/internal/service"
)

// adminInfo carries admin authority on the request context (spec 5.1).
// isAdmin gates /admin/*; userID is the acting admin session user (audit
// actor), empty when authority came from the X-Admin-Token.
type adminInfo struct {
	isAdmin bool
	userID  string
}

type adminCtxKey struct{}

// IsAdmin reports whether the request carries admin authority (spec 5.1):
// either X-Admin-Token matches (legacy 2.5) or the session user has
// role='admin' (5.1 + AC-5-12).
func IsAdmin(r *http.Request) bool {
	info, _ := r.Context().Value(adminCtxKey{}).(*adminInfo)
	return info != nil && info.isAdmin
}

// AdminUserID returns the session user id when admin authority came from a
// logged-in admin (audit actor); empty for token auth.
func AdminUserID(r *http.Request) string {
	info, _ := r.Context().Value(adminCtxKey{}).(*adminInfo)
	if info == nil {
		return ""
	}
	return info.userID
}

// requireAdmin gates every /admin/* route (spec 5.1, AC-5-1). Fail closed.
// introspect (optional, may be nil) resolves a bearer access token to its
// subject — tokens carrying role=admin pass (spec 5.16, AC-5-12).
func requireAdmin(pool *pgxpool.Pool, sessionSvc *service.SessionService, adminToken string,
	introspect func(ctx context.Context, token string) string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Legacy admin token (spec 2.5) — constant-time compare.
		if adminToken != "" &&
			subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Admin-Token")), []byte(adminToken)) == 1 {
			ctx := context.WithValue(r.Context(), adminCtxKey{}, &adminInfo{isAdmin: true})
			next(w, r.WithContext(ctx))
			return
		}

		// 2. Bearer access token whose subject has role=admin (spec 5.16).
		if introspect != nil {
			if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				if subject := introspect(r.Context(), strings.TrimPrefix(auth, "Bearer ")); subject != "" {
					if role, err := userRole(r.Context(), pool, subject); err == nil && role == "admin" {
						ctx := context.WithValue(r.Context(), adminCtxKey{}, &adminInfo{isAdmin: true, userID: subject})
						next(w, r.WithContext(ctx))
						return
					}
				}
			}
		}

		// 3. Admin session (spec 5.1): cookie session whose user has role=admin.
		if sessionSvc != nil && pool != nil {
			if sid := service.GetSessionIDFromRequest(r); sid != "" {
				if sess, err := sessionSvc.Get(r.Context(), sid); err == nil && sess != nil && sess.UserID != "" {
					if role, err := userRole(r.Context(), pool, sess.UserID); err == nil && role == "admin" {
						ctx := context.WithValue(r.Context(), adminCtxKey{}, &adminInfo{isAdmin: true, userID: sess.UserID})
						next(w, r.WithContext(ctx))
						return
					}
				}
			}
		}

		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
	}
}

func userRole(ctx context.Context, pool *pgxpool.Pool, userID string) (string, error) {
	var role string
	err := pool.QueryRow(ctx, `SELECT role FROM auth.users WHERE id = $1`, userID).Scan(&role)
	return role, err
}
