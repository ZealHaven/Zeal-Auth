# Plan 1-9: Full Integration Test Suite

**Spec:** `docs/specs/1-mvp.md §6`, all acceptance criteria
**Depends on:** all previous plans (1-0 through 1-8)
**Estimated scope:** 3-4 Go test files, ~500 lines

---

## Context

Full end-to-end integration tests that exercise the complete auth platform as a black box. Uses the real Docker Compose stack (Postgres + Redis) with `httptest`. Validates every acceptance criteria from the spec in a single coherent test suite. Each earlier plan had unit tests for its own code — this plan tests the whole system working together.

## Task

### 1. Test infrastructure (`internal/handler/integration_test.go`)

```go
func TestMain(m *testing.M) {
    // Connect to real DB + Redis (from env or Docker Compose)
    // Run migrations (fresh each run)
    // Seed test client (client_id="test-app", redirect_uri="http://localhost:9999/callback")
    // Generate initial signing key
    // Start httptest.Server with full router
    code := m.Run()
    // Cleanup
    os.Exit(code)
}
```

Config via env: `TEST_DATABASE_URL`, `TEST_REDIS_URL`. Fall back to `docker compose` defaults.

### 2. Shared test helpers (`internal/handler/testhelpers_test.go`)

```go
func createTestUser(email, password string) string          // returns user_id
func verifyTestUser(userID string)                          // mark email_verified = true
func createTestClient(id, secret string, uris []string)     // seed into auth.clients
func makeRequest(method, path string, body io.Reader) *httptest.ResponseRecorder
func parseJSON(resp *httptest.ResponseRecorder) map[string]any
func extractCookie(resp *httptest.ResponseRecorder) string  // from Set-Cookie header
func generatePKCE() (challenge, verifier string)            // S256 code_challenge
```

### 3. Signup + Login integration (`internal/handler/integration_auth_test.go`)

```go
func TestE2E_Signup_ValidCredentials(t *testing.T)         // AC-SIGNUP-1
func TestE2E_Signup_DuplicateEmail(t *testing.T)           // AC-SIGNUP-2
func TestE2E_Signup_WeakPassword(t *testing.T)             // AC-SIGNUP-3
func TestE2E_Signup_InvalidEmail(t *testing.T)             // AC-SIGNUP-4
func TestE2E_Signup_PasswordNotInResponse(t *testing.T)    // AC-SIGNUP-5
func TestE2E_Login_CorrectCredentials(t *testing.T)        // AC-LOGIN-1
func TestE2E_Login_WrongPassword(t *testing.T)             // AC-LOGIN-2
func TestE2E_Login_UnknownEmail_SameResponse(t *testing.T) // AC-LOGIN-3
func TestE2E_Login_UnverifiedEmail(t *testing.T)           // AC-LOGIN-4
```

### 4. Verification + Reset integration

```go
func TestE2E_Verify_ValidToken(t *testing.T)               // AC-VERIFY-1
func TestE2E_Verify_ExpiredToken(t *testing.T)             // AC-VERIFY-2
func TestE2E_Verify_AlreadyUsed(t *testing.T)              // AC-VERIFY-3
func TestE2E_ForgotPassword_Registered(t *testing.T)       // AC-RESET-1
func TestE2E_ForgotPassword_Unregistered(t *testing.T)     // AC-RESET-2
func TestE2E_ResetPassword_Success(t *testing.T)           // AC-RESET-3
func TestE2E_ResetPassword_RevokesTokens(t *testing.T)     // AC-RESET-3 (verify refresh tokens revoked)
func TestE2E_ResetPassword_InvalidToken(t *testing.T)      // AC-RESET-4
func TestE2E_ResetPassword_ExpiredToken(t *testing.T)      // AC-RESET-5
```

### 5. Full OAuth2 + PKCE flow integration

```go
func TestE2E_AuthorizeCodeFlow_FullCycle(t *testing.T)     // AC-AUTHZ-1: /authorize → code → /token → tokens
func TestE2E_AuthorizeCodeFlow_BadRedirectURI(t *testing.T) // AC-AUTHZ-2
func TestE2E_AuthorizeCodeFlow_BadClientID(t *testing.T)   // AC-AUTHZ-3
func TestE2E_TokenExchange_CodeReplay(t *testing.T)        // AC-AUTHZ-5
func TestE2E_TokenExchange_WrongVerifier(t *testing.T)     // AC-AUTHZ-6
func TestE2E_TokenExchange_ExpiredCode(t *testing.T)       // AC-AUTHZ-7
func TestE2E_AuthorizeFlow_MissingChallenge(t *testing.T)  // AC-AUTHZ-8
func TestE2E_RefreshFlow_Rotation(t *testing.T)            // AC-TOKEN-3
func TestE2E_RefreshFlow_ReuseDetection(t *testing.T)      // AC-TOKEN-4
func TestE2E_RefreshFlow_RevokedToken(t *testing.T)        // AC-TOKEN-5
func TestE2E_TokenResponse_Claims(t *testing.T)            // AC-TOKEN-6: id_token has sub, iss, aud
```

### 6. OIDC + JWKS integration

```go
func TestE2E_Discovery_Document(t *testing.T)              // AC-OIDC-1
func TestE2E_JWKS_ReturnsKeys(t *testing.T)                // AC-OIDC-2
func TestE2E_JWT_LocalVerification(t *testing.T)           // AC-TOKEN-1: verify against JWKS
func TestE2E_JWT_Expired(t *testing.T)                     // AC-TOKEN-2
```

### 7. Session integration

```go
func TestE2E_Session_SetOnLogin(t *testing.T)              // AC-SESSION-1
func TestE2E_Session_AutoApprove(t *testing.T)             // AC-SESSION-2
func TestE2E_Session_Missing_ShowsLogin(t *testing.T)      // AC-SESSION-3
func TestE2E_Session_Logout(t *testing.T)                  // AC-SESSION-4
```

### 8. Client registry integration

```go
func TestE2E_Client_Create_SecretShownOnce(t *testing.T)   // AC-CLIENT-1
func TestE2E_Client_Disable_RejectsAuthorize(t *testing.T) // AC-CLIENT-3
```

### 9. Run command

```bash
# Full suite
go test ./internal/handler/ -run "TestE2E" -v -count=1

# Specific area
go test ./internal/handler/ -run "TestE2E_AuthorizeCodeFlow" -v
```

## Acceptance Criteria

- [ ] All 34 ACs from spec covered by at least one `TestE2E_*` test
- [ ] Tests use real Postgres + Redis (no mocks)
- [ ] Each test is independent (unique emails, fresh data or cleanup)
- [ ] `go test ./internal/handler/ -run "TestE2E" -v` passes with 0 failures
- [ ] Full OAuth2 code exchange flow tested end-to-end (authorize → token → validate JWT)
- [ ] Refresh token rotation + theft detection tested
- [ ] Session auto-approve + logout tested
- [ ] User enumeration prevention verified (login + forgot-password identical responses)

## Files touched

- `internal/handler/integration_test.go` (TestMain + helpers)
- `internal/handler/testhelpers_test.go`
- `internal/handler/integration_auth_test.go`
- `internal/handler/integration_oauth_test.go`
- `internal/handler/integration_session_test.go`
- `internal/handler/integration_oidc_test.go`
