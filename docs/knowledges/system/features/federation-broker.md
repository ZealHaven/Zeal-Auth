---
feature: federation-broker
status: delivered
specs: [docs/specs/1-mvp.md §4.1]
plans: [docs/plans/1-6-federation-broker.md]
commits: (see git log)
---

# Federation Broker (Google + GitHub)

## What Was Built

Identity brokering: users can sign up and log in via Google or GitHub OAuth. The auth platform acts as an OAuth2 client of these IdPs, exchanges authorization codes for tokens, fetches and normalizes profile data, then creates or links local accounts. State-based CSRF protection uses Redis with one-time-use tokens.

## Position in the Auth Platform

Sits alongside email/password auth as an alternative login method. Users hitting `/oauth/google` or `/oauth/github` are redirected to the IdP, and upon callback the broker either creates a new user (email_verified=true, password_hash=NULL), links to an existing user by email, or returns the already-linked user. This feeds into the session layer (plan 1-7) for session establishment.

## Data Model

| Table | Key Columns | Purpose |
|-------|------------|---------|
| `auth.users` | `id`, `email`, `password_hash` (nullable), `email_verified` | Existing user table; social users have NULL password_hash |
| `auth.federated_identities` | `id`, `user_id` (FK→users), `provider`, `provider_user_id`, `email_at_provider` | Links local users to IdP identities. UNIQUE(provider, provider_user_id) |

**Relationships:** `federated_identities.user_id` → `users.id` (CASCADE DELETE). One user can have multiple federated identities (e.g., both Google and GitHub).

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/oauth/google` | Initiate Google OAuth — redirects to Google authorize URL |
| GET | `/oauth/google/callback` | Google callback — exchanges code, creates/links user, returns JSON |
| GET | `/oauth/github` | Initiate GitHub OAuth — redirects to GitHub authorize URL |
| GET | `/oauth/github/callback` | GitHub callback — same flow as Google |

**Callback response (success):** `{"message":"Login successful","user_id":"<uuid>"}`  
**Callback response (link required):** Redirect to `/link-account?provider=<provider>&email=<email>`  
**Callback response (error):** Redirect to `/login?error=<error_code>`

## Architecture

**Backend files:**

| File | Purpose |
|------|---------|
| `internal/model/federated.go` | FederatedIdentity model struct |
| `internal/repository/federated.go` | FindByIdentity, FindByUserID, Link, CreateUserWithoutPassword |
| `internal/service/broker.go` | Initiate (state generation + Redis store), HandleCallback (code exchange → profile fetch → user create/link), Google/GitHub profile fetchers |
| `internal/handler/broker_handler.go` | HTTP handlers for /oauth/* routes |
| `internal/handler/handler.go` | Route wiring (Broker field in RouterDeps) |
| `cmd/server/main.go` | DI wiring (Redis client, OAuth2 configs, broker service) |

**Key patterns:**
- State stored in Redis key `oauth:state:<state>` with 10min TTL, deleted on use (one-time CSRF token)
- Profile URLs overridable via `BrokerDeps` for test mocking (miniredis + httptest.NewServer)
- `CreateUserWithoutPassword` inserts with `password_hash=NULL, email_verified=true`
- Handler returns JSON for API callers; redirect-based for browser flows (link-account, login errors)

## Known Issues / Deferred Work

- **Session cookie not set on callback** — handler returns JSON; session cookie integration deferred to plan 1-7 (sessions)
- **Account linking UI** — `/link-account` page not yet implemented; redirect only. Full UI in plan 1-8
- **E2E tests** — unit/integration tests cover all 23 cases with mocked IdP; full-router E2E tests planned in plan 1-9 (`TestE2E_Broker_*`)
- **GitHub email edge case** — if user has no public email and no verified primary email, flow may fail silently
