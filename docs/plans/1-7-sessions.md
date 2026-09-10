# Plan 1-7: SSO Session Management

**Spec:** `docs/specs/1-mvp.md §4.3, §4.4, §4.5`, AC-SESSION-1–4
**Depends on:** 1-5
**Estimated scope:** 1 Go file, ~120 lines

---

## Context

Shared SSO session cookie on the auth domain. Valid session allows silent auth across products. Redis-backed session store for revocation support.

## Task

### 1. Session service (`internal/service/session.go`)

```go
type Session struct {
    ID        string    // random 32-byte hex
    UserID    uuid.UUID
    ClientID  string    // originating client
    ExpiresAt time.Time
}

type SessionService struct {
    rdb *redis.Client
    ttl time.Duration  // 30 days for MVP
}
```

Methods:
- `Create(ctx, userID, clientID string) (*Session, error)`
  - Generate random session ID
  - Store in Redis: `session:{id}` → JSON of session data
  - Set TTL (30 days)
- `Get(ctx, sessionID string) (*Session, error)`
  - Lookup in Redis, return nil if expired/missing
- `Delete(ctx, sessionID string) error`
  - Remove from Redis
- `DeleteAllForUser(ctx, userID string) error`
  - Pattern: `session:*` → scan for matching user_id → delete (used by password reset)

### 2. Cookie management

```go
const (
    SessionCookieName = "sid"
    CookieDomain      = ""  // from config
    CookiePath        = "/"
    CookieMaxAge      = 30 * 24 * 3600  // 30 days in seconds
)

func SetSessionCookie(w http.ResponseWriter, sessionID, domain string) {
    http.SetCookie(w, &http.Cookie{
        Name:     SessionCookieName,
        Value:    sessionID,
        Domain:   domain,
        Path:     "/",
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
        Path:     "/",
        MaxAge:   -1,
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteLaxMode,
    })
}

func GetSessionIDFromRequest(r *http.Request) string {
    cookie, err := r.Cookie(SessionCookieName)
    if err != nil { return "" }
    return cookie.Value
}
```

### 3. Integrate with login

After successful login (email/password or social callback):
1. `sessionService.Create(ctx, userID, clientID)`
2. `SetSessionCookie(w, session.ID, config.CookieDomain)`

### 4. Integrate with /authorize

In `GET /authorize`:
1. Read session cookie
2. `sessionService.Get(ctx, sessionID)`
3. Valid session → auto-approve (skip login screen, AC-SESSION-2)
4. Invalid/missing → show login (AC-SESSION-3)

### 5. Integrate with /logout

In `GET /logout`:
1. Read session cookie
2. `sessionService.Delete(ctx, sessionID)`
3. `ClearSessionCookie(w, config.CookieDomain)` (AC-SESSION-4)

### 6. Integrate with password reset

In `ResetPassword` (plan 1-4):
- Call `sessionService.DeleteAllForUser(ctx, userID)` after updating password

## Automatic Testing

### Test file: `internal/service/session_test.go`
```go
func TestSession_Create_StoresInRedis(t *testing.T)         // session exists after create
func TestSession_Create_30DayTTL(t *testing.T)              // TTL ~30 days
func TestSession_Get_ValidSession(t *testing.T)
func TestSession_Get_ExpiredSession(t *testing.T)            // returns nil
func TestSession_Get_UnknownID(t *testing.T)                 // returns nil
func TestSession_Delete(t *testing.T)                        // session gone after delete
func TestSession_DeleteAllForUser(t *testing.T)              // all user sessions removed
```

### Test file: `internal/handler/session_handler_test.go`
```go
func TestLoginHandler_SetsCookie(t *testing.T)              // AC-SESSION-1: Set-Cookie header present
func TestLoginHandler_CookieFlags(t *testing.T)             // HttpOnly, Secure, SameSite=Lax
func TestAuthorizeHandler_WithValidSession_AutoApproves(t *testing.T) // AC-SESSION-2
func TestAuthorizeHandler_NoSession_ShowsLogin(t *testing.T)         // AC-SESSION-3
func TestAuthorizeHandler_ExpiredSession_ShowsLogin(t *testing.T)    // AC-SESSION-3
func TestLogoutHandler_ClearsCookie(t *testing.T)           // AC-SESSION-4: MaxAge=-1
func TestLogoutHandler_DeletesFromRedis(t *testing.T)       // AC-SESSION-4: gone
```

### Test file: `internal/service/session_cookie_test.go`
```go
func TestSetSessionCookie_NameDomain(t *testing.T)
func TestSetSessionCookie_HttpOnlySecureSameSite(t *testing.T)
func TestClearSessionCookie_MaxAgeNeg1(t *testing.T)
func TestGetSessionIDFromRequest_Present(t *testing.T)
func TestGetSessionIDFromRequest_Missing(t *testing.T)
```

### Verification command
```bash
go test ./internal/service/ ./internal/handler/ -run "TestSession|TestLoginHandler|TestAuthorizeHandler|TestLogoutHandler" -v -count=1
```

## Acceptance Criteria

- [ ] **AC-SESSION-1**: Login sets HttpOnly, Secure, SameSite cookie on auth domain
- [ ] **AC-SESSION-2**: Valid session → `/authorize` issues code without login screen
- [ ] **AC-SESSION-3**: Expired/missing session → login screen shown
- [ ] **AC-SESSION-4**: Logout clears cookie; next `/authorize` requires re-login
- [ ] Password reset revokes all sessions for that user
- [ ] Session TTL is 30 days
- [ ] Session stored in Redis, not in Postgres
- [ ] `go test ./internal/service/ ./internal/handler/ -run "TestSession|TestLoginHandler|TestAuthorizeHandler|TestLogoutHandler" -v` passes

## Files touched

- `internal/service/session.go`
- `internal/service/session_test.go`
- `internal/service/session_cookie_test.go`
- `internal/handler/auth_handler.go` (set cookie after login)
- `internal/handler/oauth_handler.go` (check cookie in /authorize, clear on logout)
- `internal/handler/session_handler_test.go`
- `internal/service/email.go` (delete sessions on password reset)
