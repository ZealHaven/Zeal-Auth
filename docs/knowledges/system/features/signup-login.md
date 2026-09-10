---
feature: signup-login
status: delivered
specs: [docs/specs/1-mvp.md]
plans: [docs/plans/1-3-signup-login.md]
commits: (see git log)
---

# Email + Password Signup & Login

## What Was Built
Core user registration and authentication endpoints. Signup creates unverified users with bcrypt-hashed passwords. Login validates credentials, checks email verification status, and handles social-only accounts.

## Position in Auth Platform
Foundation layer — all other features (email verification, OAuth2, sessions) depend on user accounts existing.

## Data Model

| Table | Key Columns | Notes |
|-------|-------------|-------|
| auth.users | id (uuid PK), email (text UK), password_hash (text, nullable), email_verified (bool), created_at, updated_at | password_hash nullable for social-only users |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /signup | Create account (email + password) |
| POST | /login | Authenticate user |

### Signup Request/Response
```json
// Request
{ "email": "user@example.com", "password": "securepass123" }

// 201
{ "message": "Account created. Check your email to verify." }

// 400
{ "error": "invalid_email" | "password_too_short" }

// 409
{ "error": "email_already_exists" }
```

### Login Request/Response
```json
// Request
{ "email": "user@example.com", "password": "securepass123" }

// 200
{ "message": "Login successful", "user_id": "uuid" }

// 401
{ "error": "invalid_credentials" }

// 403
{ "error": "email_not_verified" | "social_account_only" }
```

## Architecture

| Layer | File | Pattern |
|-------|------|---------|
| Model | internal/model/user.go | Plain struct |
| Repository | internal/repository/user.go | pgxpool, returns sentinel errors |
| Service | internal/service/auth.go | Business logic, bcrypt |
| Handler | internal/handler/auth_handler.go | JSON request/response |
| Router | internal/handler/handler.go | net/http ServeMux |
| Entry | cmd/server/main.go | Wires all layers |

## Key Patterns

- **Duplicate detection**: pgconn.PgError code 23505 → ErrDuplicateEmail
- **Anti-enumeration**: Unknown email and wrong password return identical 401
- **Social-only guard**: Nil password_hash → 403 social_account_only (before bcrypt check)
- **Email verification**: Login blocked until verified (email verification in plan 1-4)

## Known Issues / Deferred Work
- Email verification token generation + email sending (plan 1-4)
- Token issuance via fosite (plan 1-5)
- Rate limiting / brute-force protection (out of scope for MVP)
