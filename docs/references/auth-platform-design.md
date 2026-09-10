# Auth Platform — Architecture, Roadmap, Flows

You're building two roles into one service:
- **Provider** — issues tokens to your apps (and later 3rd-party apps), like Google acting as an IdP for others.
- **Client/Broker** — consumes Google/GitHub OAuth to onboard users without a password.

This pattern is called **identity brokering** (Keycloak, Zitadel, Ory Hydra+Kratos all do this).

## 1. Architecture

Don't hand-roll OAuth2/OIDC crypto and flow edge cases. Build on **`ory/fosite`** (Go OAuth2/OIDC framework — battle-tested, fits your Go stack) for the Provider side, and standard `golang.org/x/oauth2` for the Broker side (Google/GitHub client).

```
Client Apps (your products first, 3rd-party later)
        │  Authorization Code + PKCE
        ▼
┌─────────────────────────────┐
│   Auth Core (Go + fosite)   │  issues JWT access/ID tokens,
│  /authorize /token /userinfo│  refresh tokens, OIDC discovery
│  /.well-known  /jwks.json   │
└───────┬──────────┬──────────┘
        │          │
        ▼          ▼
  ┌──────────┐ ┌──────────┐      ┌────────────────────┐
  │ Postgres │ │  Redis   │      │  Federation Broker  │
  │ users,   │ │ sessions,│◄────►│  → Google, GitHub,  │
  │ clients, │ │ refresh  │      │    other OAuth IdPs │
  │ scopes   │ │ tok blk- │      └────────────────────┘
  └──────────┘ │ list     │
        │      └──────────┘
        ▼
  Kafka (auth events: login, token issued/revoked, signup)
  → audit log, async welcome email, future fraud detection
```

**Key decisions:**
- **JWT access + ID tokens (RS256), self-verifying via JWKS.** Your product apps validate tokens locally — no network call back to the auth service per request. This is what makes it scale.
- **Refresh tokens are opaque, stored hashed in Postgres/Redis** — revocable, rotated on use.
- **Separate Authorization Server from Resource Servers.** Auth platform *only* issues/validates identity. Your products own their own authorization logic (what a user can do), keyed off the `sub` claim.
- **Deploy:** fits your existing VPS setup (Docker Compose, Nginx, Cloudflare Tunnel) — `auth.yourdomain.com` as its own container, shared Postgres/Redis instances if you want, but give it its own DB schema/namespace from day one so it's extractable later.

## 2. Feature Roadmap

| Phase | Goal | Features |
|---|---|---|
| **0 — MVP** | Own products can log in via SSO | Email+password signup/login · Authorization Code + PKCE flow · OIDC discovery + JWKS · Google/GitHub social login (broker) · Client registry (client_id/secret, redirect_uri allowlist) · JWT access + refresh tokens · Shared SSO session cookie · Email verification, password reset |
| **1 — Harden before opening up** | Ready for 3rd-party client apps | Consent screen (scope-based) · Scope definitions per product · Refresh token rotation + revocation · Rate limiting / brute-force protection · Audit log (Kafka) · Basic admin dashboard |
| **2 — Open to others** | "Login with [You]" like Google | Developer self-service portal (register app, manage redirect URIs) · MFA (TOTP, WebAuthn) · Token introspection endpoint · Dynamic Client Registration (RFC 7591) if fully self-serve · RBAC/fine-grained scopes · Event webhooks |
| **3 — Scale & harden** | Enterprise-grade | Multi-tenancy (isolated user pools per product/org) · Anomaly/fraud detection · Session/device management + remote logout · Account-linking UI · Automated key rotation · GDPR export/delete |

Build Phase 0 fully before touching Phase 1 — a working Provider + Broker for your own products is the entire value; everything else is hardening for scale.

## 3. User Flows

### A — New user signs up via Google/GitHub (Broker)
1. User hits your login page → clicks "Continue with Google"
2. Auth platform redirects to Google's consent screen (you're a client of Google here)
3. Google redirects back with a code → Auth platform exchanges it for the user's Google profile
4. Lookup by email/`sub`:
   - Not found → create user, link Google identity, mark email verified
   - Found, no Google link yet → prompt to link accounts
5. Auth platform sets SSO session cookie, issues tokens
6. Redirect to originating app (or dashboard if direct)

### B — 3rd-party app uses you as SSO ("Login with [You]")
1. Developer registers their app in your dev portal → gets `client_id`/`client_secret`, sets `redirect_uri`
2. User clicks "Login with [You]" on their app
3. App redirects to `/authorize` with `client_id, redirect_uri, scope, state, code_challenge`
4. No session → show login (flow A applies) · Has session → skip to consent
5. Consent screen: "App X wants: email, profile" → user approves
6. Redirect to `redirect_uri` with an authorization code
7. App's backend exchanges code (+ `code_verifier`) at `/token` → gets `access_token`, `id_token`, `refresh_token`
8. App verifies the JWT locally via your JWKS — no callback needed
9. App treats the `sub` claim as the user's identity

### C — SSO across your own products (silent auth)
1. User already has a valid session cookie on `auth.yourdomain.com`
2. Opens Product B → redirects to `/authorize`
3. Auth platform sees valid session → auto-issues code, no login screen shown (`prompt=none` style)
4. Product B exchanges code → user is in, no visible redirect flicker

### D — Token refresh
1. Access token expires
2. App calls `/token` with `grant_type=refresh_token`
3. Auth platform checks revocation list (Redis), rotates refresh token, issues new pair

### E — Logout
1. User logs out anywhere → hits `/logout`, session cookie cleared
2. (Phase 2+) Back-channel or front-channel logout notifies all connected client apps to drop their sessions too
