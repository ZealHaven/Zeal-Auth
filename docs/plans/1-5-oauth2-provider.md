# Plan 1-5: OAuth2/OIDC Provider Core

**Spec:** `docs/specs/1-mvp.md §4.3, §5`, AC-AUTHZ-1–8, AC-OIDC-1–4, AC-TOKEN-1–6, AC-CLIENT-1–4, AC-SESSION-1–4
**Depends on:** 1-2, 1-3
**Estimated scope:** 4-5 Go files, ~500 lines

---

## Context

The core of the auth platform: fosite-powered OAuth2 provider implementing Authorization Code + PKCE, JWT access/ID tokens, refresh tokens, OIDC discovery, and JWKS. This is the largest plan — it wires together fosite's storage layer with our Postgres schema.

## Task

### 1. Client registry

**Repository (`internal/repository/client.go`):**
```go
CreateClient(ctx, id, secretHash, name string, redirectURIs []string) error
GetClient(ctx, id string) (*Client, error)
DisableClient(ctx, id string) error  // sets status='disabled', revokes all tokens
GetRedirectURIs(ctx, clientID string) ([]string, error)
```

**Handler:**
- For MVP, seed clients via SQL or a `/admin/clients` endpoint (minimal, no auth needed yet)
- AC-CLIENT-1: client_secret stored hashed, shown once on creation
- AC-CLIENT-2: redirect_uri exact match enforced at `/authorize`
- AC-CLIENT-3: disabling client rejects all `/authorize` + `/token`
- AC-CLIENT-4: client_id unique regardless of display name

### 2. fosite storage adapter (`internal/storage/fosite.go`)

Implement fosite's `Storage` interface backed by our Postgres tables:

```go
type FositeStorage struct {
    db *pgxpool.Pool
}

// Required fosite interfaces:
// - Storage (core)
// - everything needed for AuthorizeCodeGrant storage
```

Key methods:
- `CreateAuthorizeCodeSession(ctx, code string, request *fosite.Request) error`
- `GetAuthorizeCodeSession(ctx, code string, session fosite.Session) (*fosite.Request, error)`
- `DeleteAuthorizeCodeSession(ctx, code string) error`
- `InvalidateAuthorizeCodeSession(ctx, code string) error`
- `CreateAccessTokenSession(ctx, token string, request *fosite.Request) error`
- `GetAccessTokenSession(ctx, token string, session fosite.Session) (*fosite.Request, error)`
- `DeleteAccessTokenSession(ctx, token string) error`
- `CreateRefreshTokenSession(ctx, token string, request *fosite.Request) error`
- `GetRefreshTokenSession(ctx, token string, session fosite.Session) (*fosite.Request, error)`
- `DeleteRefreshTokenSession(ctx, token string) error`
- `RevokeRefreshToken(ctx, token string) error`
- `RevokeAccessToken(ctx, token string) error`
- `ClientStorage` methods for client lookup

### 3. fosite server setup (`internal/handler/fosite_server.go`)

```go
func NewFositeServer(db *pgxpool.Pool, keyService *KeyService, config *Config) *fosite.OAuth2
```

Configure fosite:
- OAuth2 config: `AuthCodeLifespan = 5min`, `AccessTokenLifespan = 15min`, `RefreshTokenLifespan = 720h`
- PKCE: enable `PKCEEnforced` for public clients
- JWT: use our signing keys from `internal/service/keys.go`
- Scopes: `openid`, `profile`, `email` (fixed for MVP)

### 4. Authorization endpoint (`/authorize`)

**Handler (`internal/handler/oauth_handler.go`):**

`GET /authorize?client_id=X&redirect_uri=Y&scope=openid&state=RANDOM&code_challenge=HASH&code_challenge_method=S256&response_type=code&prompt=`

Flow:
1. Validate `client_id` exists and is active → 400 if not (AC-AUTHZ-3)
2. Validate `redirect_uri` exact match against client's allowlist → reject before redirect (AC-AUTHZ-2)
3. Validate `code_challenge` present (PKCE mandatory) → 400 if missing for public clients (AC-AUTHZ-8)
4. Check SSO session cookie:
   - Valid session → auto-approve, skip login screen
   - No session → redirect to `/login?return_to=/authorize?...` (AC-SESSION-2, AC-SESSION-3)
5. On approval → fosite creates authorize code, store with `code_challenge`
6. Redirect to `redirect_uri?code=CODE&state=STATE`

### 5. Token endpoint (`/token`)

`POST /token`
```
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=CODE&redirect_uri=URI&client_id=ID&code_verifier=VERIFIER
```

or:

```
grant_type=refresh_token&refresh_token=TOKEN&client_id=ID
```

**Authorization Code exchange:**
- fosite validates code + code_verifier (S256 comparison)
- Issues: access_token (JWT), id_token (JWT), refresh_token (opaque)
- Code invalidated after use (AC-AUTHZ-4)
- Replayed code → rejected, tokens revoked (AC-AUTHZ-5)
- Invalid verifier → `invalid_grant` (AC-AUTHZ-6)
- Expired code → rejected (AC-AUTHZ-7)

**Refresh token grant:**
- Rotate refresh token: issue new pair, invalidate old (AC-TOKEN-3)
- Reused (already-rotated) refresh token → revoke entire family (AC-TOKEN-4, theft detection)
- Revoked token → never redeemable (AC-TOKEN-5)

### 6. JWT signing

Access token claims:
```json
{
  "iss": "https://auth.yourdomain.com",
  "sub": "user-uuid",
  "aud": "client-id",
  "exp": 1234567890,
  "iat": 1234567890,
  "scope": "openid profile email"
}
```

ID token claims (OIDC):
```json
{
  "iss": "https://auth.yourdomain.com",
  "sub": "user-uuid",
  "aud": "client-id",
  "exp": 1234567890,
  "iat": 1234567890,
  "email": "user@example.com",
  "email_verified": true,
  "name": "User Name"
}
```

Sign with RS256 using key from `internal/service/keys.go`. AC-TOKEN-1: validates locally via JWKS, no callback. AC-TOKEN-6: standard OIDC claims present.

### 7. JWKS endpoint

`GET /jwks.json`
- Return all keys with status `active` or `retiring` in JWK format (AC-OIDC-4)
- Use `gopkg.in/square/go-jose.v2` or fosite's JWK helpers

### 8. OIDC discovery

`GET /.well-known/openid-configuration`
```json
{
  "issuer": "https://auth.yourdomain.com",
  "authorization_endpoint": "https://auth.yourdomain.com/authorize",
  "token_endpoint": "https://auth.yourdomain.com/token",
  "userinfo_endpoint": "https://auth.yourdomain.com/userinfo",
  "jwks_uri": "https://auth.yourdomain.com/jwks.json",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email"],
  "code_challenge_methods_supported": ["S256"]
}
```

### 9. UserInfo endpoint

`GET /userinfo` (with `Authorization: Bearer <access_token>`)
- Validate access token
- Return: `sub`, `email`, `email_verified`, `name`

### 10. Logout

`GET /logout`
- Clear session cookie
- Redirect to `/login` or provided `post_logout_redirect_uri`

## Automatic Testing

### Test file: `internal/repository/client_test.go`
```go
func TestClientRepo_Create(t *testing.T)
func TestClientRepo_GetClient(t *testing.T)
func TestClientRepo_DisableClient(t *testing.T)        // AC-CLIENT-3
func TestClientRepo_GetRedirectURIs(t *testing.T)
func TestClientRepo_DuplicateID_Fails(t *testing.T)    // AC-CLIENT-4
```

### Test file: `internal/storage/fosite_test.go`
```go
func TestFositeStorage_CreateGetAuthCode(t *testing.T)
func TestFositeStorage_InvalidateAuthCode(t *testing.T)
func TestFositeStorage_CreateGetAccessToken(t *testing.T)
func TestFositeStorage_RefreshToken_Rotation(t *testing.T)   // AC-TOKEN-3
func TestFositeStorage_RefreshToken_ReuseDetection(t *testing.T) // AC-TOKEN-4
func TestFositeStorage_RefreshToken_Revoke(t *testing.T)    // AC-TOKEN-5
func TestFositeStorage_ClientLookup(t *testing.T)            // AC-CLIENT-1
```

### Test file: `internal/handler/oauth_handler_test.go`
```go
// Authorization Code + PKCE
func TestAuthorize_ValidRequest(t *testing.T)                // AC-AUTHZ-1: code returned
func TestAuthorize_InvalidRedirectURI(t *testing.T)          // AC-AUTHZ-2: rejected
func TestAuthorize_InvalidClientID(t *testing.T)             // AC-AUTHZ-3: 400
func TestAuthorize_MissingCodeChallenge(t *testing.T)        // AC-AUTHZ-8: rejected
func TestAuthorize_WithSession_AutoApproves(t *testing.T)    // AC-SESSION-2

// Token exchange
func TestToken_CodeExchange_Success(t *testing.T)            // AC-AUTHZ-4: tokens issued
func TestToken_CodeExchange_Replay(t *testing.T)             // AC-AUTHZ-5: rejected, tokens revoked
func TestToken_CodeExchange_WrongVerifier(t *testing.T)      // AC-AUTHZ-6: invalid_grant
func TestToken_CodeExchange_Expired(t *testing.T)            // AC-AUTHZ-7: rejected
func TestToken_RefreshGrant_Success(t *testing.T)            // AC-TOKEN-3: rotated
func TestToken_RefreshGrant_ReuseRevokesFamily(t *testing.T) // AC-TOKEN-4

// JWT validation
func TestJWT_LocalVerification(t *testing.T)                // AC-TOKEN-1: validates via JWKS
func TestJWT_ExpiredToken_Rejected(t *testing.T)            // AC-TOKEN-2
func TestJWT_StandardClaims(t *testing.T)                   // AC-TOKEN-6: sub, iss, aud, exp, iat

// OIDC
func TestDiscovery_ValidDocument(t *testing.T)              // AC-OIDC-1
func TestJWKS_ReturnsActiveKeys(t *testing.T)               // AC-OIDC-2
func TestJWKS_IncludesRetiringKeys(t *testing.T)            // AC-OIDC-4

// UserInfo
func TestUserInfo_ValidToken(t *testing.T)                  // returns sub, email, email_verified
func TestUserInfo_InvalidToken(t *testing.T)                // 401

// Logout
func TestLogout_ClearsSession(t *testing.T)                 // AC-SESSION-4
```

### Verification command
```bash
go test ./internal/repository/ ./internal/storage/ ./internal/handler/ -run "TestClient|TestFosite|TestAuthorize|TestToken|TestJWT|TestDiscovery|TestJWKS|TestUserInfo|TestLogout" -v -count=1
```

## Acceptance Criteria

- [ ] **AC-AUTHZ-1–8**: All authorization code + PKCE acceptance criteria pass
- [ ] **AC-OIDC-1–4**: Discovery, JWKS, key validation, rotation all work
- [ ] **AC-TOKEN-1–6**: JWT validation, expiry, refresh rotation, theft detection, revocation
- [ ] **AC-CLIENT-1–4**: Client CRUD, exact redirect_uri match, disable revokes tokens
- [ ] **AC-SESSION-1–4**: Session cookie set on login, auto-approve with valid session, cleared on logout
- [ ] Token response contains `access_token`, `token_type`, `refresh_token`, `expires_in`, `id_token`
- [ ] Access token TTL = 15 min, refresh token TTL = 30 days
- [ ] `go test ./internal/repository/ ./internal/storage/ ./internal/handler/ -run "TestClient|TestFosite|TestAuthorize|TestToken|TestJWT|TestDiscovery|TestJWKS|TestUserInfo|TestLogout" -v` passes

## Files touched

- `internal/repository/client.go`
- `internal/repository/client_test.go`
- `internal/storage/fosite.go`
- `internal/storage/fosite_test.go`
- `internal/handler/fosite_server.go`
- `internal/handler/oauth_handler.go`
- `internal/handler/oauth_handler_test.go`
- `internal/handler/handler.go` (wire `/authorize`, `/token`, `/userinfo`, `/.well-known/*`, `/jwks.json`, `/logout`)
- `internal/model/client.go`
