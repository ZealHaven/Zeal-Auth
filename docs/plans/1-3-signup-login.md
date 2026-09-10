# Plan 1-3: Email + Password Signup & Login

**Spec:** `docs/specs/1-mvp.md §4.1, §4.2`, AC-SIGNUP-1–5, AC-LOGIN-1–4
**Depends on:** 1-1
**Estimated scope:** 2 Go files, ~250 lines

---

## Context

Core user registration and authentication. Signup creates unverified users; login requires verified email. Passwords hashed with bcrypt. Generic error messages to prevent user enumeration.

## Task

### 1. User model (`internal/model/user.go`)

```go
type User struct {
    ID            uuid.UUID
    Email         string
    PasswordHash  *string  // nullable
    EmailVerified bool
    CreatedAt     time.Time
    UpdatedAt     time.Time
}
```

### 2. User repository (`internal/repository/user.go`)

```go
type UserRepository interface {
    Create(ctx, email, passwordHash string) (*User, error)          // returns error on duplicate
    GetByEmail(ctx, email string) (*User, error)                     // nil if not found
    GetByID(ctx, id uuid.UUID) (*User, error)
    MarkEmailVerified(ctx, id uuid.UUID) error
}
```

Implementation uses `pgxpool.Pool`, queries against `auth.users`.

### 3. Auth service (`internal/service/auth.go`)

**Signup:**
- Validate email format (regex or `net/mail`)
- Validate password: ≥ 8 chars (keep simple for MVP)
- Hash password with `bcrypt.GenerateFromPassword`
- Insert user via repo
- On conflict (duplicate email) → return descriptive error
- Generate email verification token, queue email (see 1-4)

**Login:**
- Look up user by email
- Not found → generic "invalid credentials" (same as wrong password)
- Found but `password_hash` is nil → social-only account, return specific error
- Verify password with `bcrypt.CompareHashAndPassword`
- Wrong password → generic "invalid credentials"
- `email_verified == false` → return explicit "email not verified" error
- Success → return user (token issuance handled by fosite in plan 1-5)

### 4. Handler (`internal/handler/auth_handler.go`)

**POST /signup**
```json
// Request
{ "email": "user@example.com", "password": "securepass123" }

// Response 201
{ "message": "Account created. Check your email to verify." }

// Response 400 (validation)
{ "error": "email_required" | "invalid_email" | "password_too_short" }

// Response 409
{ "error": "email_already_exists" }
```

**POST /login**
```json
// Request
{ "email": "user@example.com", "password": "securepass123" }

// Response 200
{ "message": "Login successful", "user_id": "uuid" }
// NOTE: actual token issuance comes in plan 1-5 via fosite

// Response 401
{ "error": "invalid_credentials" }

// Response 403
{ "error": "email_not_verified" }

// Response 403
{ "error": "social_account_only" }
```

### 5. Wire into router

In `internal/handler/handler.go`, add routes:
```go
r.Post("/signup", h.Signup)
r.Post("/login", h.Login)
```

## Automatic Testing

### Test file: `internal/repository/user_test.go`
```go
func TestUserRepo_Create_Success(t *testing.T)
func TestUserRepo_Create_DuplicateEmail(t *testing.T)
func TestUserRepo_GetByEmail_Found(t *testing.T)
func TestUserRepo_GetByEmail_NotFound(t *testing.T)
func TestUserRepo_GetByID_Found(t *testing.T)
func TestUserRepo_MarkEmailVerified(t *testing.T)
```

### Test file: `internal/service/auth_test.go`
```go
func TestSignup_Success(t *testing.T)                  // AC-SIGNUP-1: user created, unverified
func TestSignup_DuplicateEmail(t *testing.T)            // AC-SIGNUP-2: 409
func TestSignup_WeakPassword(t *testing.T)              // AC-SIGNUP-3: 400
func TestSignup_InvalidEmail(t *testing.T)              // AC-SIGNUP-4: 400
func TestSignup_PasswordNotReturned(t *testing.T)       // AC-SIGNUP-5: response has no password_hash
func TestLogin_Success(t *testing.T)                    // AC-LOGIN-1: 200
func TestLogin_WrongPassword(t *testing.T)              // AC-LOGIN-2: 401
func TestLogin_UnknownEmail_SameResponse(t *testing.T)  // AC-LOGIN-3: 401 same body as wrong password
func TestLogin_UnverifiedEmail(t *testing.T)            // AC-LOGIN-4: 403
func TestLogin_SocialOnlyAccount(t *testing.T)          // 403 social_account_only
func TestLogin_PasswordIsBcrypt(t *testing.T)           // verify stored hash starts with $2
```

### Test file: `internal/handler/auth_handler_test.go`
```go
func TestSignupHandler_201(t *testing.T)                // HTTP level: 201 + JSON body
func TestSignupHandler_409_Duplicate(t *testing.T)      // HTTP level: 409
func TestSignupHandler_400_Validation(t *testing.T)     // HTTP level: 400
func TestLoginHandler_200(t *testing.T)                 // HTTP level: 200 + user_id
func TestLoginHandler_401(t *testing.T)                 // HTTP level: 401
func TestLoginHandler_403_Unverified(t *testing.T)      // HTTP level: 403
```

### Verification command
```bash
go test ./internal/repository/ ./internal/service/ ./internal/handler/ -run "TestUser|TestSignup|TestLogin" -v -count=1
```

## Acceptance Criteria

- [ ] **AC-SIGNUP-1**: Valid email + password → user created unverified, 201
- [ ] **AC-SIGNUP-2**: Duplicate email → 409, no duplicate record
- [ ] **AC-SIGNUP-3**: Password < 8 chars → 400 with validation detail
- [ ] **AC-SIGNUP-4**: Malformed email → 400
- [ ] **AC-SIGNUP-5**: Password stored bcrypt, never in any response
- [ ] **AC-LOGIN-1**: Correct credentials + verified → 200
- [ ] **AC-LOGIN-2**: Wrong password → 401
- [ ] **AC-LOGIN-3**: Unknown email → 401 identical to wrong password
- [ ] **AC-LOGIN-4**: Unverified email → 403 "email_not_verified"
- [ ] Social-only user (nil password_hash) → 403 "social_account_only"
- [ ] `go test ./internal/repository/ ./internal/service/ ./internal/handler/ -run "TestUser|TestSignup|TestLogin" -v` passes

## Files touched

- `internal/model/user.go`
- `internal/repository/user.go`
- `internal/repository/user_test.go`
- `internal/service/auth.go`
- `internal/service/auth_test.go`
- `internal/handler/auth_handler.go`
- `internal/handler/auth_handler_test.go`
- `internal/handler/handler.go` (add routes)
