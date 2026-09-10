# MVP (Phase 0) — Acceptance Criteria

Scoped strictly to Phase 0 features. Rate limiting, consent screen, and admin dashboard are Phase 1 — not tested here.

## 1. Email + password signup
- **AC-SIGNUP-1** Valid email + password meeting policy → user created as unverified, verification email queued, `201`.
- **AC-SIGNUP-2** Email already registered → `409`, no duplicate record created.
- **AC-SIGNUP-3** Password fails policy (length/complexity) → `400` with validation detail, no user created.
- **AC-SIGNUP-4** Malformed email → `400`.
- **AC-SIGNUP-5** Password is stored hashed (bcrypt/argon2) — never plaintext, never returned in any response.

## 2. Email + password login
- **AC-LOGIN-1** Correct credentials, verified account → session/tokens issued.
- **AC-LOGIN-2** Incorrect password → `401`, no session created.
- **AC-LOGIN-3** Account does not exist → generic `401` identical to AC-LOGIN-2 (no user enumeration).
- **AC-LOGIN-4** Unverified email → login blocked with an explicit "verify your email" response, not a generic failure.

## 3. Email verification
- **AC-VERIFY-1** Valid, unexpired token → account marked verified, `200`.
- **AC-VERIFY-2** Expired or invalid token → `400`/`410`, account stays unverified.
- **AC-VERIFY-3** Token is single-use — reusing a spent token returns an explicit "already verified" state, not an error loop.

## 4. Password reset
- **AC-RESET-1** `POST /forgot-password` on a registered email → reset token generated + emailed.
- **AC-RESET-2** Same endpoint on an unregistered email → identical `200` response (no enumeration).
- **AC-RESET-3** Valid token + policy-compliant new password → password updated, and **all existing sessions and refresh tokens for that user are revoked**.
- **AC-RESET-4** Expired, invalid, or already-used token → `400`, password unchanged.
- **AC-RESET-5** Reset token is single-use and time-boxed (≤ ~60 min).

## 5. Social login — Google / GitHub (broker)
- **AC-BROKER-1** Click "Continue with Google" → correct authorize URL built with `state` and your registered redirect_uri.
- **AC-BROKER-2** Valid callback code → exchanged for profile (email, sub, name, email_verified).
- **AC-BROKER-3** No existing user matches → new user created, email marked verified (trusting the IdP), identity linked.
- **AC-BROKER-4** Existing user with matching email but no linked identity → account-link prompt shown, not silently auto-merged.
- **AC-BROKER-5** Existing user already linked → logs straight in, session established.
- **AC-BROKER-6** Missing or mismatched `state` on callback → rejected, no session created (CSRF protection).
- **AC-BROKER-7** IdP returns an error or user denies consent → redirected back to login with a plain, non-technical message.
- **AC-BROKER-8** AC-BROKER-1 through 7 all hold identically for the GitHub broker.

## 6. Authorization Code + PKCE (provider)
- **AC-AUTHZ-1** Registered client_id + allow-listed redirect_uri + `code_challenge` → on approval, a short-lived, single-use authorization code is returned to redirect_uri with `state`.
- **AC-AUTHZ-2** redirect_uri not in that client's allowlist → rejected before any redirect (blocks open-redirect).
- **AC-AUTHZ-3** Unknown/invalid client_id → `400`, no code issued.
- **AC-AUTHZ-4** `/token` with correct code + matching `code_verifier` → access, ID, and refresh tokens issued; code invalidated.
- **AC-AUTHZ-5** `/token` with an already-redeemed code → rejected, **and every token previously issued from that code is revoked** (replay protection).
- **AC-AUTHZ-6** `/token` with missing/incorrect `code_verifier` → `invalid_grant`.
- **AC-AUTHZ-7** Code not redeemed within its TTL (e.g. 60s–10min) → expired, rejected.
- **AC-AUTHZ-8** Public client omits `code_challenge` → rejected (PKCE mandatory for public clients).

## 7. OIDC discovery + JWKS
- **AC-OIDC-1** `GET /.well-known/openid-configuration` → valid document listing issuer, endpoints, supported scopes/response types.
- **AC-OIDC-2** `GET /jwks.json` → current signing key(s) in valid JWK format.
- **AC-OIDC-3** A token signed with the currently published key validates successfully against that JWKS response.
- **AC-OIDC-4** During key rotation, both old and new keys are published simultaneously so tokens signed before rotation still validate.

## 8. Client registry
- **AC-CLIENT-1** Registering a client generates a unique client_id and client_secret; secret is shown once, stored hashed thereafter.
- **AC-CLIENT-2** redirect_uri matching is exact — no partial or prefix matches accepted at `/authorize`.
- **AC-CLIENT-3** Disabling a client rejects all further `/authorize` and `/token` calls for it, and invalidates its existing tokens.
- **AC-CLIENT-4** client_id is always unique even if two clients share a display name.

## 9. JWT access + refresh tokens
- **AC-TOKEN-1** A valid access token validates locally via JWKS with no call back to the auth service.
- **AC-TOKEN-2** An access token past its TTL (e.g. 15 min) is rejected by resource servers as expired.
- **AC-TOKEN-3** `grant_type=refresh_token` with a valid refresh token → new access+refresh pair issued, old refresh token invalidated (rotation).
- **AC-TOKEN-4** A refresh token that's already been rotated is reused (replay) → request rejected **and the whole token family is revoked** (theft detection).
- **AC-TOKEN-5** A revoked refresh token (logout, password reset, client disabled) can never be redeemed again.
- **AC-TOKEN-6** ID tokens contain standard OIDC claims (`sub`, `iss`, `aud`, `exp`, `iat`) plus any requested profile/email claims.

## 10. Shared SSO session cookie
- **AC-SESSION-1** Login on one product sets a session cookie on the shared auth domain, flagged `HttpOnly`, `Secure`, `SameSite`.
- **AC-SESSION-2** Valid session cookie present → a second product's `/authorize` call issues a code with no login screen shown.
- **AC-SESSION-3** Expired or missing session cookie → login screen shown.
- **AC-SESSION-4** Logout clears/invalidates the session cookie; the next `/authorize` call requires re-login.
