package handler

import (
	"net/http"

	"github.com/zeal/auth/internal/service"
)

// requireSession gates self-service routes (spec 5.7/5.9/5.6 settings) on a
// valid sid cookie; passes the user id to next.
func requireSession(sessionSvc *service.SessionService, next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if sessionSvc == nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		sid := service.GetSessionIDFromRequest(r)
		if sid == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		sess, err := sessionSvc.Get(r.Context(), sid)
		if err != nil || sess == nil || sess.UserID == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r, sess.UserID)
	}
}
