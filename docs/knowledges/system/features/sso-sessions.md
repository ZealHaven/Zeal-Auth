---
feature: sso-sessions
status: delivered
specs: [docs/specs/1-mvp.md]
plans: [docs/plans/1-7-sessions.md]
commits: (see git log)
---

# SSO Session Management

## What Was Built
Redis-backed session service with shared cookie across auth domain. Sessions are created on login (email/password or social), checked in `/authorize` for auto-approve, and deleted on logout and password reset.

## Position in Auth Platform
Middle layer — sits between authentication (signup/login) and authorization (OAuth2 `/authorize`). Enables silent auth across products via shared session cookie.

## Data Model

Sessions live in Redis, not Postgres.

| Key Pattern | Value | TTL |
|-------------|-------|-----|
| `session:{id}` | JSON `{id, user_id, client_id, expires_at}` | 30 days |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /login | Sets session cookie on success |
| POST | /login-form | HTML form login, sets session cookie |
| GET | /authorize | Checks session cookie for auto-approve |
| GET | /logout | Deletes session from Redis, clears cookie |
| POST | /reset-password | Deletes all sessions for user |

## Architecture

| Layer | File | Pattern |
|-------|------|---------|
| Service | internal/service/session.go | Redis CRUD, 30-day TTL |
| Cookie helpers | internal/service/session.go | Set/Clear/GetSessionID |
| Auth handler | internal/handler/auth_handler.go | Creates session after login |
| OAuth handler | internal/handler/oauth_handler.go | Reads session in /authorize, deletes in /logout |
| Broker handler | internal/handler/broker_handler.go | Creates session on social login |
| Email service | internal/service/email.go | DeleteAllForUser on password reset |
| Tests | internal/service/session_test.go, session_cookie_test.go | miniredis-based unit tests |
| Integration | internal/handler/integration_session_test.go | Full router + real Redis tests |

## Key Patterns

- **Cookie name**: `sid` (was `sso_session` pre-plan)
- **Cookie flags**: HttpOnly, Secure, SameSite=Lax, 30-day MaxAge
- **Session ID**: 32-byte random hex
- **TTL enforcement**: Redis handles expiry; app checks for nil on Get
- **Password reset**: Calls `DeleteAllForUser` to revoke all sessions
- **Social login**: Broker handler creates session on successful callback

## Known Issues / Deferred Work
- Session cookie domain is hardcoded from config; multi-tenant domain routing not implemented
- No session listing/revocation admin endpoint
- Scan-based `DeleteAllForUser` may be slow at scale (acceptable for MVP)
