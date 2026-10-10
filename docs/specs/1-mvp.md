# Auth Platform — MVP Spec (Phase 0)

**Goal:** Own products can log in via centralized SSO. No 3rd-party onboarding yet.

**Stack:** Go + fosite (OAuth2/OIDC), Postgres, Redis, Docker Compose, Cloudflare Tunnel.
**Domain:** `auth.yourdomain.com`

**Progress (2026-10-09):** core implemented + verified via `TestE2E_AuthorizeCodeFlow_HappyPath` and live smoke; spec 3 complete (silent SSO, logout revocation, JWKS local-validation, check-email URLs). Legend: ✅ done · ⚠️ partial/untested · ❌ not done. **Remaining ❌ items all point at specs 4/5 — this doc is fully delegated; treat those specs as the backlog.**

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

> ✅ All tables created by `migrations/000001` + `000002`.
> ⚠️ **Deviation:** `authorization_codes` and `refresh_tokens` tables exist but fosite does not use them — token/code sessions live in `auth.fosite_requests` (keyed JSONB, `Invalidated` flag instead of `used_at`/`replaced_by_id`). Spec tables kept for future direct queries. `clients.status="disabled"` honored in `GetClient` (returns not-found), but no admin endpoint sets it yet (→ spec 5, AC-CLIENT-3).

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

### Auth Core — all ✅ implemented (+ extras: `POST /revoke`, `POST /introspect`, `POST /admin/clients`, `GET /health`)

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

### Federation Broker — all ✅ implemented

| Method | Path | Purpose |
|--------|------|---------|
| GET | /oauth/google | Initiate Google OAuth |
| GET | /oauth/google/callback | Handle Google callback |
| GET | /oauth/github | Initiate GitHub OAuth |
| GET | /oauth/github/callback | Handle GitHub callback |

---

## 4. Flows

### A — New user signs up via Google/GitHub ✅ (code + tests; link-prompt flow completed in spec 2.7)
1. User clicks "Continue with Google" → auth redirects to Google consent
2. Google redirects back with code → auth exchanges for profile
3. Lookup by email/sub:
   - Not found → create user, link identity, mark email verified
   - Found, no linked identity → prompt to link accounts
4. Set SSO session cookie, issue tokens
5. Redirect to originating app

### B — Authorization Code + PKCE (for your products) ✅ (happy-path E2E verified incl. PKCE, JWKS-published ID tokens)
1. Product redirects to `/authorize` with `client_id, redirect_uri, scope, state, code_challenge`
2. No session → show login. Has session → auto-issue code
3. On approval → short-lived single-use code returned to redirect_uri with state
4. Product exchanges code + code_verifier at `/token` → access, ID, refresh tokens
5. Product verifies JWT locally via JWKS

### C — SSO across products (silent auth) ✅ (spec 3: `TestE2E_SilentSSO_TwoClients` — two clients, session → authorize client 2, no login prompt)
1. User has valid session on auth.yourdomain.com
2. Opens Product B → redirects to `/authorize`
3. Valid session → auto-issue code, no login screen

### D — Token refresh ✅ (rotation + old-token rejection + family revocation verified)
1. Access token expires (15 min TTL)
2. App calls `/token` with `grant_type=refresh_token`
3. Auth checks revocation list, rotates refresh token, issues new pair

### E — Logout ✅ (session cleared + user's fosite tokens revoked; tests: `TestE2E_Session_Logout`, `TestE2E_Logout_RevokesRefreshToken`, e2e `session.spec.ts`)
1. User hits `/logout` → session cookie cleared, refresh/access tokens deleted (spec 3, AC-3-6)

---

## 5. Screens (UI)

> ✅ All screens implemented (templates in `templates/`; includes link-account prompt not listed below).
> ✅ URL conformance (spec 3, 3.9): `/signup/check-email` and `/forgot-password/check-email` both resolve; signup form redirects to `/signup/check-email`.

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

*(✅ = test-backed or smoke-verified · ⚠️ implemented, not directly asserted · ❌ not done)*

### Email + Password Signup
- ✅ **AC-SIGNUP-1** Valid email + password → user created unverified, verification email queued, `201`.
- ✅ **AC-SIGNUP-2** Duplicate email → `409`, no record created. (`TestSignupHandler_409_Duplicate`)
- ✅ **AC-SIGNUP-3** Weak password → `400` with validation detail. (`auth_test` ErrPasswordTooShort)
- ✅ **AC-SIGNUP-4** Malformed email → `400`.
- ✅ **AC-SIGNUP-5** Password stored hashed (bcrypt/argon2), never plaintext, never in any response.

### Email + Password Login
- ✅ **AC-LOGIN-1** Correct credentials + verified → session/tokens issued.
- ✅ **AC-LOGIN-2** Wrong password → `401`.
- ✅ **AC-LOGIN-3** Unknown email → generic `401` identical to AC-LOGIN-2 (no enumeration).
- ✅ **AC-LOGIN-4** Unverified email → explicit "verify your email" response, not generic failure.

### Email Verification
- ✅ **AC-VERIFY-1** Valid, unexpired token → account marked verified, `200`.
- ✅ **AC-VERIFY-2** Expired/invalid token → `400`/`410`, account stays unverified.
- ✅ **AC-VERIFY-3** Spent token → "already verified" state, not error loop.

### Password Reset
- ✅ **AC-RESET-1** `POST /forgot-password` on registered email → reset token generated + emailed (now via Mailer, spec 2.4).
- ✅ **AC-RESET-2** Unregistered email → identical `200` (no enumeration).
- ✅ **AC-RESET-3** Valid token + compliant new password → password updated, **all existing sessions + refresh tokens revoked**. (`TestResetPassword_RevokesFositeTokens` asserts fosite token deletion + non-target survival)
- ✅ **AC-RESET-4** Invalid/expired/used token → `400`, password unchanged.
- ✅ **AC-RESET-5** Token single-use, time-boxed (≤ 60 min).

### Social Login (Broker)
- ✅ **AC-BROKER-1** "Continue with Google" → correct authorize URL with `state` + redirect_uri. (`TestGoogleInitiate_RedirectsToGoogle`)
- ✅ **AC-BROKER-2** Valid callback code → exchanged for profile (email, sub, name, email_verified).
- ✅ **AC-BROKER-3** No matching user → new user created, email verified, identity linked. (`TestBroker_HandleCallback_NewUser`)
- ✅ **AC-BROKER-4** Existing user, no linked identity → account-link prompt, not auto-merge. (link flow completed in spec 2.7; `TestBroker_BeginCompleteLink`)
- ✅ **AC-BROKER-5** Existing user already linked → logs in, session established. (`TestBroker_HandleCallback_ExistingLinkedUser`)
- ✅ **AC-BROKER-6** Missing/mismatched `state` → rejected, no session (CSRF protection).
- ✅ **AC-BROKER-7** IdP error/denied consent → redirected to login with plain message.
- ✅ **AC-BROKER-8** AC-BROKER-1–7 hold identically for GitHub. (integration_broker GitHub cases)

### Authorization Code + PKCE (Provider)
- ✅ **AC-AUTHZ-1** Registered client_id + allowlisted redirect_uri + code_challenge → short-lived, single-use code returned with state. (`TestE2E_AuthorizeCodeFlow_HappyPath`)
- ✅ **AC-AUTHZ-2** Unknown redirect_uri → rejected before redirect (blocks open-redirect). (`TestE2E_AuthorizeCodeFlow_BadRedirectURI`)
- ✅ **AC-AUTHZ-3** Invalid client_id → `400`. (`TestE2E_AuthorizeCodeFlow_BadClientID`)
- ✅ **AC-AUTHZ-4** `/token` with correct code + code_verifier → tokens issued; code invalidated. (happy-path)
- ✅ **AC-AUTHZ-5** Redeemed code reused → rejected, tokens from that code revoked (replay protection). (happy-path replay step)
- ✅ **AC-AUTHZ-6** Missing/incorrect code_verifier → `invalid_grant`. (`TestE2E_Token_Guards` wrong-verifier; missing challenge tested at `/authorize`)
- ✅ **AC-AUTHZ-7** Code past TTL → expired, rejected. (`TestE2E_Token_Guards` ages stored code session)
- ✅ **AC-AUTHZ-8** Public client omits code_challenge → rejected (PKCE mandatory).

### OIDC Discovery + JWKS
- ✅ **AC-OIDC-1** `GET /.well-known/openid-configuration` → valid document with issuer, endpoints, scopes. (`TestE2E_Discovery_Document`; endpoints now truthful per spec 2.6)
- ✅ **AC-OIDC-2** `GET /jwks.json` → current signing keys in JWK format. (`TestE2E_JWKS_ReturnsKeys`)
- ✅ **AC-OIDC-3** JWT signed with published key validates against JWKS. (`TestE2E_ReferenceClient_JWKSVerify` — signature verified against `/jwks.json`, flipped signature rejected; spec 3, AC-3-7)
- ❌ **AC-OIDC-4** During rotation, both old + new keys published simultaneously. `GetAllActiveKeys` supports it; rotation has no caller yet (→ spec 4, 4.6).

### Client Registry
- ✅ **AC-CLIENT-1** Register client → unique client_id + secret; secret shown once, stored hashed. (`TestE2E_Client_Create_SecretShownOnce`; gated by admin token since spec 2.5)
- ✅ **AC-CLIENT-2** redirect_uri matching is exact — no prefix/partial. (BadRedirectURI test)
- ❌ **AC-CLIENT-3** Disabling client → rejects all further `/authorize` + `/token`, invalidates existing tokens. `GetClient` honors `status`, but no endpoint to disable (→ spec 5, 5.3).
- ✅ **AC-CLIENT-4** client_id always unique regardless of display name.

### JWT Tokens
- ✅ **AC-TOKEN-1** Valid ID/access token validates locally via JWKS, no callback to auth service. (`TestE2E_ReferenceClient_JWKSVerify`; spec 3, AC-3-7. Note: profile claims still come from `/userinfo` — signature+`sub`/`iss` validate locally.)
- ✅ **AC-TOKEN-2** Access token past TTL (15 min) → rejected. (`TestE2E_Token_Guards` ages stored access-token session → userinfo 401)
- ✅ **AC-TOKEN-3** `grant_type=refresh_token` with valid token → new access+refresh pair; old refresh invalidated (rotation).
- ✅ **AC-TOKEN-4** Replayed refresh token → rejected, whole token family revoked (theft detection).
- ✅ **AC-TOKEN-5** Revoked refresh token (logout, password reset, client disabled) → never redeemable. Password reset ✅ (`TestResetPassword_RevokesFositeTokens`); logout ✅ (spec 3, `TestE2E_Logout_RevokesRefreshToken`); client disabled n/a → **spec 5, AC-CLIENT-3 / AC-5-2**.
- ✅ **AC-TOKEN-6** ID tokens contain `sub`, `iss`, `aud`, `exp`, `iat` + profile/email claims. (happy-path asserts claims incl. `email`)

### SSO Session Cookie
- ✅ **AC-SESSION-1** Login sets session cookie on auth domain: `HttpOnly`, `Secure`, `SameSite`.
- ✅ **AC-SESSION-2** Valid session → second product's `/authorize` issues code, no login screen. (`TestE2E_Session_AutoApprove` + `TestE2E_SilentSSO_TwoClients` — true two-client scenario; spec 3, AC-3-3)
- ✅ **AC-SESSION-3** Expired/missing session → login screen shown. (`TestE2E_Session_Missing_ShowsLogin`)
- ✅ **AC-SESSION-4** Logout clears session cookie; next `/authorize` requires re-login. (`TestE2E_Session_Logout` + e2e)

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

## 8. Out of Scope (Phase 1+) — now tracked in specs 3–5

> Moved out of this document; each item lives in the spec that owns it.

- Consent screen (scope-based) → **spec 5, 5.10**
- Scope definitions per product → **spec 5, 5.10**
- Rate limiting / brute-force protection → **spec 4, 4.5**
- Audit log (Kafka) → **spec 5, 5.5** (DB first)
- Admin dashboard → **spec 5, 5.1–5.4**
- Developer self-service portal → **spec 5, 5.14**
- MFA (TOTP, WebAuthn) → **spec 5, 5.6**
- ~~Token introspection endpoint~~ → ✅ done in **spec 2** (`POST /introspect`)
- Dynamic Client Registration → **spec 5, 5.15**
- RBAC / fine-grained scopes → **spec 5, 5.16**
- Event webhooks → **spec 5, 5.13**
- Multi-tenancy → **spec 5 footer** (backlog beyond iteration 5)
- Session/device management + remote logout → **spec 5, 5.7**
