---
feature: email-verification-reset
status: delivered
specs: [docs/specs/1-mvp.md]
plans: [docs/plans/1-4-email-verification-reset.md]
commits: (see git log)
---

# Email Verification & Password Reset

## What Was Built
Post-signup email verification and password reset flows using time-boxed, single-use tokens stored as SHA-256 hashes. For MVP, "sending email" is a log statement (no SMTP/SES). Password reset revokes all refresh tokens for the user.

## Position in Auth Platform
Fills the identity lifecycle gap between signup (plan 1-3) and OAuth2/OIDC (future plans). Users must verify email before login. Password reset provides account recovery.

## Data Model

| Table | Key Columns | Notes |
|-------|-------------|-------|
| `auth.email_verification_tokens` | `id`, `user_id` FK→users, `token_hash`, `expires_at`, `used_at` | TTL 24h, single-use |
| `auth.password_reset_tokens` | `id`, `user_id` FK→users, `token_hash`, `expires_at`, `used_at` | TTL 60min, single-use |

Both tables cascade delete on `user_id`. Raw tokens never stored — only SHA-256 hash.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/verify?token=<raw>` | Verify email. 200 success/already-verified, 400 invalid, 410 expired |
| POST | `/forgot-password` | Request reset. Always 200 (no email enumeration) |
| POST | `/reset-password` | Set new password with token. Revokes all refresh tokens |

## Architecture

**New files:**
- `internal/service/token.go` — `GenerateToken()` (32-byte random hex), `HashToken()` (SHA-256)
- `internal/service/email.go` — `EmailService` — verify, forgot-password, reset-password business logic
- `internal/model/token.go` — `VerificationToken`, `ResetToken` structs
- `internal/repository/verification.go` — CRUD for `email_verification_tokens`
- `internal/repository/reset.go` — CRUD for `password_reset_tokens`
- `internal/service/token_test.go` — 5 tests
- `internal/service/email_test.go` — 17 tests
- `internal/handler/auth_handler_verify_test.go` — 7 tests

**Modified files:**
- `internal/handler/auth_handler.go` — Added `VerifyEmail`, `ForgotPassword`, `ResetPassword` handlers; Signup now generates verification token
- `internal/handler/handler.go` — Wired 3 new routes
- `cmd/server/main.go` — Creates verification/reset repos + `EmailService`
- `internal/handler/auth_handler_test.go` — Updated `setupHandlerTest` to create `EmailService`

## Known Issues / Deferred Work
- Email sending is `log.Printf` only — no SMTP/SES integration yet
- No resend-verification-token endpoint
- Tests require `-p 1` when running handler + service together — both `TestMain` functions drop/recreate the `auth` schema, causing race conditions under parallel execution (pre-existing test isolation issue)
- No session cookie invalidation on password reset (Redis session layer not yet implemented)
