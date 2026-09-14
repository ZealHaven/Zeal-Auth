---
feature: integration-tests
status: delivered
specs: [docs/specs/1-mvp.md]
plans: [docs/plans/1-9-integration-tests.md]
commits: (see git log)
---

# Integration Test Suite

## What Was Built
Two-tier integration testing: Go E2E tests (httptest against full router with real Postgres + Redis) and Playwright E2E tests (real server binary + Chromium browser). Covers all MVP acceptance criteria.

## Position in Auth Platform
Quality layer — validates entire system working together: signup → verify → login → session → authorize → token → logout.

## Test Tiers

### Go E2E Tests (`TestE2E_*`)
84 handler tests total, 34 E2E tests covering:

| Area | File | Tests |
|------|------|-------|
| Signup + Login | integration_auth_test.go | 9 tests (valid, duplicate, weak, invalid, unverified, wrong password, enumeration) |
| Verify + Reset | integration_verify_reset_test.go | 10 tests (valid/expired/used tokens, forgot password, reset + revoke) |
| OAuth2 + OIDC | integration_oauth_test.go | 5 tests (discovery, JWKS, bad redirect/client, missing PKCE) |
| Sessions | integration_session_test.go | 4 tests (set on login, missing session, logout) |
| Broker | integration_broker_test.go | 6 tests (Google/GitHub initiate, bad state, missing params, client create) |
| Helpers | testhelpers_test.go | Shared: createTestUser, generatePKCE, extractCookie, etc. |

### Playwright E2E Tests
27 browser tests covering:

| Area | File | Tests |
|------|------|-------|
| Signup flow | e2e/auth.spec.ts | 6 tests (page, valid, duplicate, weak, social buttons, login link) |
| Login flow | e2e/auth.spec.ts | 5 tests (page, wrong password, forgot link, social buttons, signup link) |
| Forgot password | e2e/auth.spec.ts | 3 tests (page, submit, back link) |
| Verify email | e2e/auth.spec.ts | 1 test (invalid token) |
| Root route | e2e/auth.spec.ts | 2 tests (redirect to /login, 404) |
| UI design | e2e/auth.spec.ts | 2 tests (dark theme colors) |
| API endpoints | e2e/auth.spec.ts | 3 tests (health, OIDC discovery, JWKS) |
| Sessions | e2e/session.spec.ts | 4 tests (authorize redirect, logout, post-logout, link-account) |

## Architecture

| Component | File | Purpose |
|-----------|------|---------|
| Test main | internal/handler/auth_handler_test.go | Merges unit + integration TestMain (shared pool, miniredis) |
| Integration setup | internal/handler/integration_test.go | buildIntegRouter(), cleanIntegDB() |
| Playwright config | playwright.config.ts | Points to e2e/ dir, globalSetup/Teardown |
| Server lifecycle | e2e/global-setup.ts | Builds binary, runs migrations, starts server on :9876 |
| Teardown | e2e/global-teardown.ts | Kills server process, frees port |
| Test helpers | e2e/helpers.ts | baseURL() reads port from file |

## Key Patterns

- **Shared TestMain**: Single TestMain initializes both `testPool` (Postgres) and `integRDB` (miniredis), used by unit tests and E2E tests
- **Real server E2E**: Playwright tests build Go binary, start it as detached process, run Chromium against it, tear down
- **Port file**: global-setup writes port to `bin/.e2e-port`, helpers.ts reads it (avoids globalThis cross-process issues)
- **Password hashing**: Integration helpers use real bcrypt (not fake hashes) for login tests
- **Content negotiation**: Verify handler content-negotiates HTML/JSON based on Accept/User-Agent

## Running

```bash
just test              # All Go tests (unit + integration)
just test-integration  # E2E Go tests only (TestE2E_*)
just test-e2e          # Playwright browser tests (starts real server)
```

## Known Issues / Deferred Work
- Google/GitHub social login E2E tests require real OAuth credentials (currently only unit-tested with mock IdPs)
- Parallel TestMain conflict between handler/storage/service packages when running `go test ./...` (works fine with `-p 1`)
