# Plan 1-4: Email Verification & Password Reset

**Spec:** `docs/specs/1-mvp.md §4.1, §4.2`, AC-VERIFY-1–3, AC-RESET-1–5
**Depends on:** 1-3
**Estimated scope:** 2 Go files, ~200 lines

---

## Context

Email verification (post-signup) and password reset flows. Both use time-boxed, single-use tokens stored as SHA-256 hashes. For MVP, "sending email" is a log statement + mock (no SMTP/SES yet).

## Task

### 1. Token generation

Utility function (can live in `internal/service/token.go` or similar):
```go
func GenerateToken() string  // 32-byte random hex
func HashToken(token string) string  // SHA-256 hex
```

### 2. Email verification

**Repository (`internal/repository/verification.go`):**
```go
CreateVerificationToken(ctx, userID uuid.UUID, tokenHash string, expiresAt time.Time) error
GetVerificationToken(ctx, tokenHash string) (*VerificationToken, error)
MarkTokenUsed(ctx, id uuid.UUID) error
```

**Service:**
- On signup (called from `internal/service/auth.go`):
  - Generate raw token
  - Store hash in `auth.email_verification_tokens`
  - TTL: 24 hours
  - Log the verification URL: `GET /verify?token=<raw_token>`
- `VerifyEmail(token string)`:
  - Hash token, look up in DB
  - Not found → 400 "invalid_token"
  - `used_at` not null → 200 "already_verified" (not error)
  - `expires_at` past → 410 "token_expired"
  - Valid → mark `used_at = now()`, mark user `email_verified = true`
  - Return success

**Handler (`internal/handler/auth_handler.go`):**

**GET /verify?token=xxx**
```
// Response 200
{ "message": "Email verified successfully" }

// Response 200 (already verified)
{ "message": "Email already verified" }

// Response 400
{ "error": "invalid_token" }

// Response 410
{ "error": "token_expired" }
```

### 3. Password reset

**Repository (`internal/repository/reset.go`):**
```go
CreateResetToken(ctx, userID uuid.UUID, tokenHash string, expiresAt time.Time) error
GetResetToken(ctx, tokenHash string) (*ResetToken, error)
MarkTokenUsed(ctx, id uuid.UUID) error
```

**Service:**
- `RequestPasswordReset(email string)`:
  - Look up user by email
  - Not found → still return 200 (no enumeration)
  - Found → generate token, store hash with 60-min TTL
  - Log the reset URL: `POST /reset-password` with token
- `ResetPassword(token, newPassword string)`:
  - Validate password ≥ 8 chars
  - Hash token, look up in DB
  - Not found → 400 "invalid_token"
  - `used_at` not null → 400 "token_already_used"
  - `expires_at` past → 400 "token_expired"
  - Valid → hash new password, update user
  - **Revoke all refresh tokens for this user** (AC-RESET-3)
  - **Delete all session cookies** (invalidate in Redis if using session IDs)
  - Mark token used

**Handler:**

**POST /forgot-password**
```json
// Request
{ "email": "user@example.com" }

// Response 200 (always, even if email not found)
{ "message": "If an account exists, a reset link has been sent." }
```

**POST /reset-password**
```json
// Request
{ "token": "raw_token", "password": "newsecurepass" }

// Response 200
{ "message": "Password updated successfully" }

// Response 400
{ "error": "invalid_token" | "token_expired" | "password_too_short" }
```

### 4. Session revocation on reset

In `ResetPassword`, after updating the password:
- Query `auth.refresh_tokens WHERE user_id = ? AND revoked_at IS NULL`
- Set `revoked_at = now()` for all
- Delete session from Redis (key pattern: `session:<user_id>` or similar)

### 5. Wire routes

```go
r.Get("/verify", h.VerifyEmail)
r.Post("/forgot-password", h.ForgotPassword)
r.Post("/reset-password", h.ResetPassword)
```

## Automatic Testing

### Test file: `internal/service/token_test.go`
```go
func TestGenerateToken_Length(t *testing.T)            // returns 64-char hex string
func TestHashToken_Deterministic(t *testing.T)         // same input → same hash
func TestHashToken_DifferentInputs(t *testing.T)       // different tokens → different hashes
```

### Test file: `internal/service/email_test.go`
```go
func TestVerifyEmail_ValidToken(t *testing.T)           // AC-VERIFY-1: 200, user verified
func TestVerifyEmail_ExpiredToken(t *testing.T)         // AC-VERIFY-2: 410
func TestVerifyEmail_InvalidToken(t *testing.T)         // AC-VERIFY-2: 400
func TestVerifyEmail_AlreadyUsed(t *testing.T)          // AC-VERIFY-3: 200 "already_verified"
func TestVerifyEmail_TokenIsSingleUse(t *testing.T)    // use twice → second time fails
func TestForgotPassword_RegisteredEmail(t *testing.T)   // AC-RESET-1: 200, token created
func TestForgotPassword_UnregisteredEmail(t *testing.T) // AC-RESET-2: 200 (no enumeration)
func TestForgotPassword_SameResponseForBoth(t *testing.T) // AC-RESET-2: identical response
func TestResetPassword_ValidToken(t *testing.T)         // AC-RESET-3: password updated
func TestResetPassword_TokenSingleUse(t *testing.T)     // AC-RESET-5: reuse fails
func TestResetPassword_InvalidToken(t *testing.T)       // AC-RESET-4: 400
func TestResetPassword_ExpiredToken(t *testing.T)       // AC-RESET-4: 400
func TestResetPassword_WeakPassword(t *testing.T)       // 400 password_too_short
func TestResetPassword_RevokesRefreshTokens(t *testing.T) // AC-RESET-3: all tokens revoked
func TestResetPassword_RevokesSessions(t *testing.T)    // Redis sessions deleted
func TestVerificationToken_TTL24h(t *testing.T)         // expires_at = created_at + 24h
func TestResetToken_TTL60m(t *testing.T)                // expires_at = created_at + 60min
func TestVerificationToken_OnlyHashStored(t *testing.T)  // raw token not in DB
```

### Test file: `internal/handler/auth_handler_verify_test.go`
```go
func TestVerifyHandler_200(t *testing.T)
func TestVerifyHandler_200_AlreadyVerified(t *testing.T)
func TestVerifyHandler_400_InvalidToken(t *testing.T)
func TestVerifyHandler_410_Expired(t *testing.T)
func TestForgotPasswordHandler_200(t *testing.T)
func TestResetPasswordHandler_200(t *testing.T)
func TestResetPasswordHandler_400(t *testing.T)
```

### Verification command
```bash
go test ./internal/service/ ./internal/handler/ -run "TestVerify|TestForgot|TestReset|TestToken_" -v -count=1
```

## Acceptance Criteria

- [ ] **AC-VERIFY-1**: Valid unexpired token → verified, 200
- [ ] **AC-VERIFY-2**: Expired/invalid → 400/410
- [ ] **AC-VERIFY-3**: Spent token → "already_verified" (not error)
- [ ] **AC-RESET-1**: Registered email → token generated + logged, 200
- [ ] **AC-RESET-2**: Unregistered email → identical 200
- [ ] **AC-RESET-3**: Valid token + new password → password updated, all refresh tokens revoked
- [ ] **AC-RESET-4**: Invalid/expired/used token → 400
- [ ] **AC-RESET-5**: Token single-use, 60-min TTL
- [ ] Verification token TTL is 24 hours
- [ ] Raw token never stored — only SHA-256 hash
- [ ] `go test ./internal/service/ ./internal/handler/ -run "TestVerify|TestForgot|TestReset|TestToken_" -v` passes

## Files touched

- `internal/repository/verification.go`
- `internal/repository/reset.go`
- `internal/service/token.go`
- `internal/service/token_test.go`
- `internal/service/email.go`
- `internal/service/email_test.go`
- `internal/handler/auth_handler.go` (add 3 routes)
- `internal/handler/auth_handler_verify_test.go`
- `internal/handler/handler.go` (wire routes)
