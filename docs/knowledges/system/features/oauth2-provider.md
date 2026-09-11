---
feature: oauth2-provider
status: delivered
specs: [docs/specs/1-mvp.md]
plans: [docs/plans/1-5-oauth2-provider.md]
commits: 0d7486e
---

# OAuth2/OIDC Provider Core

## What Was Built

Fosite-powered OAuth2 provider implementing Authorization Code + PKCE, opaque access/refresh tokens, JWT ID tokens (RS256), OIDC discovery, JWKS, and token introspection. Client registry with exact redirect_uri matching, disable-to-revoke, and secret hashed storage. SSO session cookie support with auto-approve on valid session.

## Position in System

Core of the auth platform. All product apps authenticate users via this provider's `/authorize` → `/token` flow. Sits between client apps and the Postgres-backed user/identity store.

## Data Model

| Table | Purpose |
|-------|---------|
| `auth.clients` | OAuth2 client registrations (id PK, secret_hash, name, status) |
| `auth.client_redirect_uris` | Allowed redirect URIs per client (exact match) |
| `auth.fosite_requests` | Serialized fosite.Request objects keyed by token signature (SHA-256 for auth codes, HMAC for tokens) |
| `auth.access_tokens` | Access token tracking for revocation (signature, request_id, expires_at, revoked_at) |
| `auth.client_assertions` | JTI tracking for client_assertion JWTs (replay prevention) |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/authorize` | OAuth2 authorization code + PKCE entry. Redirects to `/login` if no session, auto-approves with valid session. |
| POST | `/token` | Token exchange: auth code → tokens, refresh token → new pair. Returns access_token, refresh_token, id_token. |
| GET | `/userinfo` | Returns claims for valid Bearer access token (sub, email, email_verified, name). |
| GET | `/.well-known/openid-configuration` | OIDC discovery document. |
| GET | `/jwks.json` | Active + retiring signing keys in JWK format. |
| GET | `/logout` | Clears SSO session cookie, redirects to post_logout_redirect_uri or /login. |
| POST | `/admin/clients` | Creates OAuth2 client (shown once). No auth yet — MVP. |

## Architecture

**Files:**
- `internal/handler/fosite_server.go` — fosite provider construction: config, HMAC + JWT strategies, handler wiring (auth code, refresh, PKCE, OIDC, revocation, introspection)
- `internal/handler/oauth_handler.go` — HTTP handlers for all OAuth2/OIDC endpoints, openidSession type (implements fosite.Session), SSO session cookie management, CreateClient admin endpoint
- `internal/handler/handler.go` — RouterDeps struct, route registration
- `internal/storage/fosite.go` — Postgres-backed fosite storage adapter. Implements ClientManager, CoreStorage, OpenIDConnectRequestStorage. Serializes fosite.Request as JSON in `auth.fosite_requests`. Token signatures used as keys.
- `internal/repository/client.go` — Client CRUD (Create, GetClient, DisableClient, GetRedirectURIs) with transactional redirect URI insertion
- `internal/model/client.go` — Client + ClientRedirectURI structs
- `internal/service/keys.go` — Added KeyService type wrapping pool + encKey, with GetActivePrivateKey, GetActivePublicKeyPEM, GetAllActiveKeys, ParseRSAPublicKeyPEM
- `cmd/server/main.go` — Wired KeyService, FositeConfig, OAuthHandler, OAuth2Handler into RouterDeps

**Strategies:**
- Auth codes: HMAC-SHA (opaque)
- Access tokens: HMAC-SHA (opaque) — spec wanted JWT but fosite's compose doesn't cleanly support pure JWT access tokens; opaque is standard for MVP
- ID tokens: JWT RS256 via `openid.DefaultStrategy` + `jwt.DefaultSigner`
- Refresh tokens: HMAC-SHA (opaque)

**Storage adapter pattern:** fosite passes raw token strings to storage methods. `FositeStorage` hashes them (SHA-256 for auth codes, uses HMAC signature for tokens) to create Postgres keys. Full fosite.Request serialized as JSON in `auth.fosite_requests` table. Session data hydrated on retrieval via `json.Unmarshal` into the concrete session type.

## Known Issues / Deferred Work

- **Access tokens are opaque, not JWT** — fosite's `AuthorizeExplicitGrantHandler` uses a single `AccessTokenStrategy`; switching to JWT requires a custom composite strategy. Low priority since product apps use ID tokens for identity and introspect access tokens for authorization.
- **PKCE storage not wired to Postgres** — fosite's PKCE handler uses its own storage interface; currently backed by MemoryStore. Needs `CreatePKCERequestSession` etc. added to FositeStorage.
- **No client authentication** — `/admin/clients` has no auth. Phase 1+ adds developer portal.
- **Session management is minimal** — SSO session cookie validated via refresh_tokens table lookup. No Redis-backed session store yet.
- **RedirectSecureChecker allows localhost** — dev mode only; prod needs HTTPS enforcement.
- **Client grant_types/response_types are hardcoded** — always `authorization_code, refresh_token` and `code`. Should come from client registration.
- **Tests share DB across packages** — require `-p 1` flag to avoid race conditions between TestMain functions.
