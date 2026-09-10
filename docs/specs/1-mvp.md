# Auth Platform — MVP Spec (Phase 0)

**Goal:** Own products can log in via centralized SSO. No 3rd-party onboarding yet.

**Stack:** Go + fosite (OAuth2/OIDC), Postgres, Redis, Docker Compose, Cloudflare Tunnel.
**Domain:** `auth.yourdomain.com`

---

## 1. Architecture

```
Client Apps (your products)
        │  Authorization Code + PKCE
        ▼
┌─────────────────────────────┐
│   Auth Core (Go + fosite)   │  /authorize /token /userinfo
│   /.well-known  /jwks.json  │
└───────┬──────────┬──────────┘
        │          │
        ▼          ▼
  ┌──────────┐ ┌──────────┐      ┌────────────────────┐
  │ Postgres │ │  Redis   │      │  Federation Broker  │
  │ users,   │ │ sessions,│◄────►│  Google, GitHub     │
  │ clients  │ │ refresh  │      └────────────────────┘
  └──────────┘ │ tok blk- │
               └──────────┘
```

- JWT access + ID tokens (RS256), self-verifying via JWKS
- Refresh tokens opaque, hashed in Postgres/Redis, revocable
- Auth service owns identity only; product apps own their own authorization
- Separate DB schema from day one (extractable later)

---

## 2. Database Schema

### users
| Column | Type | Notes |
|--------|------|-------|
| id | uuid PK | |
| email | text UK | |
| password_hash | text | nullable (social-only users) |
| email_verified | boolean | default false |
| created_at | timestamptz | |
| updated_at | timestamptz | |

### federated_identities
| Column | Type | Notes |
|--------|------|-------|
| id | uuid PK | |
| user_id | uuid FK → users | |
| provider | text | "google", "github" |
| provider_user_id | text | IdP's sub claim |
| email_at_provider | text | nullable |
| created_at | timestamptz | |

Unique constraint: (provider, provider_user_id).

### email_verification_tokens
| Column | Type | Notes |
|--------|------|-------|
| id | uuid PK | |
| user_id | uuid FK → users | |
| token_hash | text | SHA-256 of raw token |
| expires_at | timestamptz | |
| used_at | timestamptz | nullable, single-use |
| created_at | timestamptz | |

### password_reset_tokens
| Column | Type | Notes |
|--------|------|-------|
| id | uuid PK | |
| user_id | uuid FK → users | |
| token_hash | text | SHA-256 of raw token |
| expires_at | timestamptz | ≤ 60 min |
| used_at | timestamptz | nullable, single-use |
| created_at | timestamptz | |

### clients
| Column | Type | Notes |
|--------|------|-------|
| id | text PK | the client_id |
| client_secret_hash | text | bcrypt/argon2 |
| name | text | display name |
| status | text | "active" or "disabled" |
| created_at | timestamptz | |

### client_redirect_uris
| Column | Type | Notes |
|--------|------|-------|
| id | uuid PK | |
| client_id | text FK → clients | |
| redirect_uri | text | exact match only |

### authorization_codes
| Column | Type | Notes |
|--------|------|-------|
| code_hash | text PK | SHA-256 |
| client_id | text FK → clients | |
| user_id | uuid FK → users | |
| redirect_uri | text | must match client_redirect_uris |
| code_challenge | text | PKCE S256 |
| code_challenge_method | text | "S256" |
| scope | text | |
| expires_at | timestamptz | 60s–10min |
| used_at | timestamptz | nullable, single-use |
| created_at | timestamptz | |

### refresh_tokens
| Column | Type | Notes |
|--------|------|-------|
| id | uuid PK | |
| token_hash | text UK | SHA-256 |
| family_id | uuid | groups rotations for theft detection |
| user_id | uuid FK → users | |
| client_id | text FK → clients | |
| scope | text | |
| expires_at | timestamptz | |
| revoked_at | timestamptz | nullable |
| replaced_by_id | uuid FK → refresh_tokens | nullable, self-ref |
| created_at | timestamptz | |

### signing_keys
| Column | Type | Notes |
|--------|------|-------|
| id | uuid PK | |
| kid | text UK | |
| algorithm | text | "RS256" |
| public_key | text | PEM |
| private_key_encrypted | text | encrypted at rest |
| status | text | "active", "retiring", "retired" |
| created_at | timestamptz | |
| rotated_at | timestamptz | nullable |

---

## 3. API Endpoints

### Auth Core

| Method | Path | Purpose |
|--------|------|---------|
| POST | /signup | Email + password registration |
| POST | /login | Email + password authentication |
| GET | /verify | Email verification (token in query) |
| POST | /forgot-password | Request reset email |
| POST | /reset-password | Set new password with token |
| GET | /authorize | OAuth2 Authorization Code + PKCE entry |
| POST | /token | Exchange code or refresh token |
| GET | /userinfo | Returns claims for valid access token |
| GET | /.well-known/openid-configuration | OIDC discovery |
| GET | /jwks.json | Current signing keys |
| GET | /logout | Clear session, redirect |

### Federation Broker

| Method | Path | Purpose |
|--------|------|---------|
| GET | /oauth/google | Initiate Google OAuth |
| GET | /oauth/google/callback | Handle Google callback |
| GET | /oauth/github | Initiate GitHub OAuth |
| GET | /oauth/github/callback | Handle GitHub callback |

---

## 4. Flows

### A — New user signs up via Google/GitHub
1. User clicks "Continue with Google" → auth redirects to Google consent
2. Google redirects back with code → auth exchanges for profile
3. Lookup by email/sub:
   - Not found → create user, link identity, mark email verified
   - Found, no linked identity → prompt to link accounts
4. Set SSO session cookie, issue tokens
5. Redirect to originating app

### B — Authorization Code + PKCE (for your products)
1. Product redirects to `/authorize` with `client_id, redirect_uri, scope, state, code_challenge`
2. No session → show login. Has session → auto-issue code
3. On approval → short-lived single-use code returned to redirect_uri with state
4. Product exchanges code + code_verifier at `/token` → access, ID, refresh tokens
5. Product verifies JWT locally via JWKS

### C — SSO across products (silent auth)
1. User has valid session on auth.yourdomain.com
2. Opens Product B → redirects to `/authorize`
3. Valid session → auto-issue code, no login screen

### D — Token refresh
1. Access token expires (15 min TTL)
2. App calls `/token` with `grant_type=refresh_token`
3. Auth checks revocation list, rotates refresh token, issues new pair

### E — Logout
1. User hits `/logout` → session cookie cleared

---

## 5. Screens (UI)

| Screen | URL | Purpose |
|--------|-----|---------|
| Sign up | /signup | Email + password form, social buttons |
| Log in | /login | Email + password form, social buttons |
| Check inbox (signup) | /signup/check-email | Verification email sent |
| Email verified | /verify | Success state |
| Link expired | /verify | Token expired, resend option |
| Forgot password | /forgot-password | Email input |
| Reset link sent | /forgot-password/check-email | Confirmation |
| Set new password | /reset-password | New password form |
| Authorize (SSO) | /authorize?client_id=X | "Continue as [App]" banner + login |
| Redirecting | /authorize?client_id=X | Spinner, auto-redirect |

---

## 6. Acceptance Criteria

### Email + Password Signup
- **AC-SIGNUP-1** Valid email + password → user created unverified, verification email queued, `201`.
- **AC-SIGNUP-2** Duplicate email → `409`, no record created.
- **AC-SIGNUP-3** Weak password → `400` with validation detail.
- **AC-SIGNUP-4** Malformed email → `400`.
- **AC-SIGNUP-5** Password stored hashed (bcrypt/argon2), never plaintext, never in any response.

### Email + Password Login
- **AC-LOGIN-1** Correct credentials + verified → session/tokens issued.
- **AC-LOGIN-2** Wrong password → `401`.
- **AC-LOGIN-3** Unknown email → generic `401` identical to AC-LOGIN-2 (no enumeration).
- **AC-LOGIN-4** Unverified email → explicit "verify your email" response, not generic failure.

### Email Verification
- **AC-VERIFY-1** Valid, unexpired token → account marked verified, `200`.
- **AC-VERIFY-2** Expired/invalid token → `400`/`410`, account stays unverified.
- **AC-VERIFY-3** Spent token → "already verified" state, not error loop.

### Password Reset
- **AC-RESET-1** `POST /forgot-password` on registered email → reset token generated + emailed.
- **AC-RESET-2** Unregistered email → identical `200` (no enumeration).
- **AC-RESET-3** Valid token + compliant new password → password updated, **all existing sessions + refresh tokens revoked**.
- **AC-RESET-4** Invalid/expired/used token → `400`, password unchanged.
- **AC-RESET-5** Token single-use, time-boxed (≤ 60 min).

### Social Login (Broker)
- **AC-BROKER-1** "Continue with Google" → correct authorize URL with `state` + redirect_uri.
- **AC-BROKER-2** Valid callback code → exchanged for profile (email, sub, name, email_verified).
- **AC-BROKER-3** No matching user → new user created, email verified, identity linked.
- **AC-BROKER-4** Existing user, no linked identity → account-link prompt, not auto-merge.
- **AC-BROKER-5** Existing user already linked → logs in, session established.
- **AC-BROKER-6** Missing/mismatched `state` → rejected, no session (CSRF protection).
- **AC-BROKER-7** IdP error/denied consent → redirected to login with plain message.
- **AC-BROKER-8** AC-BROKER-1–7 hold identically for GitHub.

### Authorization Code + PKCE (Provider)
- **AC-AUTHZ-1** Registered client_id + allowlisted redirect_uri + code_challenge → short-lived, single-use code returned with state.
- **AC-AUTHZ-2** Unknown redirect_uri → rejected before redirect (blocks open-redirect).
- **AC-AUTHZ-3** Invalid client_id → `400`.
- **AC-AUTHZ-4** `/token` with correct code + code_verifier → tokens issued; code invalidated.
- **AC-AUTHZ-5** Redeemed code reused → rejected, tokens from that code revoked (replay protection).
- **AC-AUTHZ-6** Missing/incorrect code_verifier → `invalid_grant`.
- **AC-AUTHZ-7** Code past TTL → expired, rejected.
- **AC-AUTHZ-8** Public client omits code_challenge → rejected (PKCE mandatory).

### OIDC Discovery + JWKS
- **AC-OIDC-1** `GET /.well-known/openid-configuration` → valid document with issuer, endpoints, scopes.
- **AC-OIDC-2** `GET /jwks.json` → current signing keys in JWK format.
- **AC-OIDC-3** JWT signed with published key validates against JWKS.
- **AC-OIDC-4** During rotation, both old + new keys published simultaneously.

### Client Registry
- **AC-CLIENT-1** Register client → unique client_id + secret; secret shown once, stored hashed.
- **AC-CLIENT-2** redirect_uri matching is exact — no prefix/partial.
- **AC-CLIENT-3** Disabling client → rejects all further `/authorize` + `/token`, invalidates existing tokens.
- **AC-CLIENT-4** client_id always unique regardless of display name.

### JWT Tokens
- **AC-TOKEN-1** Valid access token validates locally via JWKS, no callback to auth service.
- **AC-TOKEN-2** Access token past TTL (15 min) → rejected.
- **AC-TOKEN-3** `grant_type=refresh_token` with valid token → new access+refresh pair; old refresh invalidated (rotation).
- **AC-TOKEN-4** Replayed refresh token → rejected, whole token family revoked (theft detection).
- **AC-TOKEN-5** Revoked refresh token (logout, password reset, client disabled) → never redeemable.
- **AC-TOKEN-6** ID tokens contain `sub`, `iss`, `aud`, `exp`, `iat` + profile/email claims.

### SSO Session Cookie
- **AC-SESSION-1** Login sets session cookie on auth domain: `HttpOnly`, `Secure`, `SameSite`.
- **AC-SESSION-2** Valid session → second product's `/authorize` issues code, no login screen.
- **AC-SESSION-3** Expired/missing session → login screen shown.
- **AC-SESSION-4** Logout clears session cookie; next `/authorize` requires re-login.

---

## 7. Key Decisions

| Decision | Rationale |
|----------|-----------|
| fosite for OAuth2/OIDC | Battle-tested Go framework; avoids hand-rolling crypto/flow edge cases |
| RS256 JWT access + ID tokens | Product apps validate locally — no network call per request, scales better |
| Opaque refresh tokens | Revocable, rotatable, stored hashed |
| PKCE mandatory for public clients | Prevents authorization code interception |
| Separate DB schema from day one | Auth platform extractable later without migrating all products |
| No consent screen in MVP | Only your own products — no need to show scope approval |
| No Kafka in MVP | Overkill for own products; add in Phase 1 |

---

## 8. Out of Scope (Phase 1+)

- Consent screen (scope-based)
- Scope definitions per product
- Rate limiting / brute-force protection
- Audit log (Kafka)
- Admin dashboard
- Developer self-service portal
- MFA (TOTP, WebAuthn)
- Token introspection endpoint
- Dynamic Client Registration
- RBAC / fine-grained scopes
- Event webhooks
- Multi-tenancy
- Session/device management + remote logout
