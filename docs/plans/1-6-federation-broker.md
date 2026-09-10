# Plan 1-6: Federation Broker (Google + GitHub)

**Spec:** `docs/specs/1-mvp.md §4.1`, AC-BROKER-1–8
**Depends on:** 1-3, 1-5
**Estimated scope:** 2 Go files, ~250 lines

---

## Context

Identity brokering: users can sign up/login via Google or GitHub OAuth. The auth platform acts as a client of these IdPs, normalizes profile data, and creates or links local accounts.

## Task

### 1. Federated identity model + repository

**Model (`internal/model/federated.go`):**
```go
type FederatedIdentity struct {
    ID               uuid.UUID
    UserID           uuid.UUID
    Provider         string  // "google", "github"
    ProviderUserID   string  // IdP's sub claim
    EmailAtProvider  *string
    CreatedAt        time.Time
}
```

**Repository (`internal/repository/federated.go`):**
```go
FindByIdentity(ctx, provider, providerUserID string) (*FederatedIdentity, error)
FindByUserID(ctx, userID uuid.UUID) ([]*FederatedIdentity, error)
Link(ctx, userID uuid.UUID, provider, providerUserID, email string) error
```

### 2. OAuth2 client configs

Using `golang.org/x/oauth2`:

**Google:**
```go
var googleConfig = &oauth2.Config{
    ClientID:     config.GoogleClientID,
    ClientSecret: config.GoogleClientSecret,
    Endpoint:     google.Endpoint,
    RedirectURL:  config.GoogleRedirectURI,  // e.g. /oauth/google/callback
    Scopes:       []string{"openid", "email", "profile"},
}
```

**GitHub:**
```go
var githubConfig = &oauth2.Config{
    ClientID:     config.GitHubClientID,
    ClientSecret: config.GitHubClientSecret,
    Endpoint: oauth2.Endpoint{
        AuthURL:  "https://github.com/login/oauth/authorize",
        TokenURL: "https://github.com/login/oauth/access_token",
    },
    RedirectURL: config.GitHubRedirectURI,
    Scopes:      []string{"user:email"},
}
```

### 3. Broker service (`internal/service/broker.go`)

**Initiate(provider, returnTo string) (authorizeURL, state, nonce string)**
- Generate random `state`
- Store `state → returnTo` mapping in Redis (TTL 10min)
- Build provider-specific authorize URL with `state`
- Return URL for redirect

**HandleCallback(provider, code, state string) (*User, error)**
1. Validate `state` exists in Redis, delete it (one-time use) — CSRF protection (AC-BROKER-6)
2. Exchange code for token via `oauth2.Config.Exchange`
3. Fetch user profile from provider:
   - Google: `GET https://www.googleapis.com/oauth2/v2/userinfo` (with Bearer token)
   - GitHub: `GET https://api.github.com/user` + `GET https://api.github.com/user/emails`
4. Normalize to: `{ email, providerUserID, name, emailVerified }`
5. Lookup by (provider, providerUserID):
   - Found → return linked user (AC-BROKER-5)
6. Lookup by email:
   - Found, no link for this provider → return "link required" signal (AC-BROKER-4)
   - Not found → create user (email_verified = true, since IdP verified), link identity (AC-BROKER-3)
7. Return user

### 4. Handlers (`internal/handler/broker_handler.go`)

**GET /oauth/google** (AC-BROKER-1)
- Call `broker.Initiate("google", returnTo)`
- Redirect to Google authorize URL
- Store state in cookie or Redis

**GET /oauth/google/callback** (AC-BROKER-2)
- Extract `code` and `state` from query
- Call `broker.HandleCallback("google", code, state)`
- On success → set SSO session cookie, redirect to originating app
- On error → redirect to `/login` with plain message (AC-BROKER-7)
- On "link required" → redirect to `/link-account?provider=google&email=...`

**GET /oauth/github** (AC-BROKER-8 — same pattern)
**GET /oauth/github/callback** (AC-BROKER-8)

### 5. Account linking prompt

When a callback hits "link required" (existing email, no linked identity):
- Redirect to `/link-account?provider=google&email=user@example.com`
- Show: "An account already exists with this email. Log in to link your Google account."
- After login → link the identity, redirect to originating app

For MVP, this is a minimal HTML page, not a full template (detailed UI in plan 1-7).

## Automatic Testing

### Test file: `internal/repository/federated_test.go`
```go
func TestFederatedRepo_Link(t *testing.T)
func TestFederatedRepo_FindByIdentity_Found(t *testing.T)     // AC-BROKER-5
func TestFederatedRepo_FindByIdentity_NotFound(t *testing.T)
func TestFederatedRepo_FindByUserID(t *testing.T)
func TestFederatedRepo_UniqueConstraint(t *testing.T)          // (provider, provider_user_id) unique
```

### Test file: `internal/service/broker_test.go`
```go
func TestBroker_Initiate_ReturnsURLWithState(t *testing.T)     // AC-BROKER-1
func TestBroker_Initiate_StateStoredInRedis(t *testing.T)
func TestBroker_HandleCallback_NewUser(t *testing.T)           // AC-BROKER-3: created, verified, linked
func TestBroker_HandleCallback_ExistingLinkedUser(t *testing.T) // AC-BROKER-5: logs in
func TestBroker_HandleCallback_UnlinkedEmail(t *testing.T)     // AC-BROKER-4: returns link_required
func TestBroker_HandleCallback_BadState(t *testing.T)          // AC-BROKER-6: error
func TestBroker_HandleCallback_StateSingleUse(t *testing.T)    // reuse state fails
func TestBroker_HandleCallback_SocialUserNoPassword(t *testing.T) // password_hash=NULL
func TestBroker_HandleCallback_EmailVerifiedTrue(t *testing.T)  // IdP-trusted
```

### Test file: `internal/handler/broker_handler_test.go`
```go
func TestGoogleInitiate_RedirectsToGoogle(t *testing.T)        // AC-BROKER-1
func TestGoogleCallback_Success(t *testing.T)                  // AC-BROKER-2
func TestGoogleCallback_BadState(t *testing.T)                 // AC-BROKER-6
func TestGoogleCallback_IdpError(t *testing.T)                 // AC-BROKER-7
func TestGitHubInitiate_RedirectsToGitHub(t *testing.T)        // AC-BROKER-8
func TestGitHubCallback_Success(t *testing.T)                  // AC-BROKER-8
```

**Note:** Broker service tests mock the upstream IdP HTTP calls using `httptest.NewServer` to simulate Google/GitHub responses. No real OAuth flows needed in tests.

### Verification command
```bash
go test ./internal/repository/ ./internal/service/ ./internal/handler/ -run "TestFederated|TestBroker|TestGoogle|TestGitHub" -v -count=1
```

## Acceptance Criteria

- [ ] **AC-BROKER-1**: Click "Continue with Google" → correct authorize URL with state + redirect_uri
- [ ] **AC-BROKER-2**: Valid callback → exchanged for profile
- [ ] **AC-BROKER-3**: No matching user → new user created, email verified, identity linked
- [ ] **AC-BROKER-4**: Existing user, no link → account-link prompt, not auto-merge
- [ ] **AC-BROKER-5**: Existing linked user → logs in, session established
- [ ] **AC-BROKER-6**: Missing/mismatched state → rejected, no session
- [ ] **AC-BROKER-7**: IdP error/denied → redirected to login with plain message
- [ ] **AC-BROKER-8**: All above hold for GitHub identically
- [ ] Social users have `password_hash = NULL`, `email_verified = true`
- [ ] `go test ./internal/repository/ ./internal/service/ ./internal/handler/ -run "TestFederated|TestBroker|TestGoogle|TestGitHub" -v` passes

## Files touched

- `internal/model/federated.go`
- `internal/repository/federated.go`
- `internal/repository/federated_test.go`
- `internal/service/broker.go`
- `internal/service/broker_test.go`
- `internal/handler/broker_handler.go`
- `internal/handler/broker_handler_test.go`
- `internal/handler/handler.go` (wire `/oauth/*` routes)
- `internal/config/config.go` (add Google/GitHub client config)
