# Auth Platform — Iteration 3: First Product Integration (Phase B)

**Goal:** First real product logs in via Zeal Auth in dev. Repeatable recipe for every future product.

**Status:** ✅ Complete (2026-10-09)
**Depends on:** 2-core-repair.md

Legend: ✅ done · ⚠️ partial · ❌ not done

---

## 1. Scope

| # | Item | Detail |
|---|------|--------|
| ✅ 3.1 | Client seeding | `just seed-client <name> <redirect-uri>` (`cmd/seed`) registers one OAuth client: id (slug), secret (shown once), exact redirect URIs. Secret bcrypt-hashed per `1-mvp.md` §2. AC-3-1 live-verified: seeded client completed `/authorize` → `/token` immediately. |
| ✅ 3.2 | Integration recipe doc | `docs/knowledges/product/integrating.md`: authorize redirect → code exchange → JWKS verify → refresh, ~30 lines per product, no SDK required. Go snippet uses `golang-jwt` + JWKS fetch with kid selection. |
| ✅ 3.3 | Dev ergonomics | `http://localhost` redirect URIs allowed (fosite `IsRedirectURISecure`: https anywhere, http only loopback — includes dev); `EMAIL_DRIVER=log` default (`config.go`); `just seed` creates verified test user `dev@example.com`/`password123` + two demo clients. Plus AC-3-4 boot fixes: `.env` auto-loaded by `config.Load`, dev fallback for empty `KEY_ENCRYPTION_KEY`, `COOKIE_DOMAIN=localhost` in `.env.example`. |
| ✅ 3.4 | Multi-client SSO check | `TestE2E_SilentSSO_TwoClients`: login → authorize client A → authorize client B, same session → code issued, no login screen. Two clients seeded by `just seed`. |
| ✅ 3.5 | First consumer integration | Reference client = `TestE2E_ReferenceClient_JWKSVerify` (full PKCE flow against local server + JWKS verify) + `docs/knowledges/product/integrating.md` recipe. Live smoke on dev server: login → authorize → exchange → JWKS verify → tampered-sig rejected → refresh → logout → refresh `invalid_grant`. |
| ✅ 3.6 | Logout revokes refresh tokens | `Logout` now runs the same `fosite_requests` subject delete as password reset before clearing the session (`oauth_handler.go`). `TestE2E_Logout_RevokesRefreshToken` asserts post-logout `invalid_grant` + other users' tokens survive. Closes AC-TOKEN-5. |
| ✅ 3.7 | JWKS local-validation assertions | Reference client verifies ID token RS256 signature against `/jwks.json` (kid match + all-keys fallback) and rejects a flipped-signature token. Closes AC-OIDC-3 + AC-TOKEN-1. |
| ✅ 3.8 | Graceful skip when pg down | `db.SkipIfNoPostgres` called from all 5 TestMains: prints `SKIP: postgres unavailable: …`, exits 0. Verified: `go test ./...` with Postgres stopped → all packages `ok`, exit 0. Closes AC-2-12 / 2.9. |
| ✅ 3.9 | Screen URL conformance | Added `GET /signup/check-email` + `GET /forgot-password/check-email` aliases; signup form now redirects to `/signup/check-email`. `TestCheckEmail_SpecScreenURLs_Resolve`. |

## 2. Acceptance Criteria

- ✅ **AC-3-1** `just seed-client <name> <redirect-uri>` → client usable at `/authorize` immediately. (live smoke 2026-10-09; `TestE2E_SilentSSO_TwoClients` for seeded-client shape)
- ✅ **AC-3-2** Reference client completes auth-code + PKCE flow against local server, verifies ID token via JWKS. (`TestE2E_ReferenceClient_JWKSVerify` + live smoke)
- ✅ **AC-3-3** Silent SSO: session from client 1 → client 2 authorize with no login prompt. (`TestE2E_SilentSSO_TwoClients`)
- ✅ **AC-3-4** New dev machine: `cp .env.example .env && just up && just migrate-up && just seed && just dev` → working login in <10 min following `docs/knowledges/product/integrating.md` only. (each step verified live: `.env` auto-load, boot with empty `KEY_ENCRYPTION_KEY`, seed, login, full flow)
- ✅ **AC-3-5** Secrets never logged or re-displayable after creation. (seed + admin API print once, bcrypt at rest; `TestE2E_Client_Create_SecretShownOnce`)
- ✅ **AC-3-6** Logout → previously issued refresh token rejected at `/token`. (`TestE2E_Logout_RevokesRefreshToken` + live smoke; closes AC-TOKEN-5)
- ✅ **AC-3-7** Reference client verifies ID token signature against JWKS; flipped signature fails. (`TestE2E_ReferenceClient_JWKSVerify`; closes AC-OIDC-3, AC-TOKEN-1)
- ✅ **AC-3-8** `go test ./...` with Postgres stopped → packages report SKIP (not panic/non-zero). (verified: exit 0, `SKIP:` message; closes AC-2-12)
- ✅ **AC-3-9** Both `/signup/check-email` and `/forgot-password/check-email` resolve. (`TestCheckEmail_SpecScreenURLs_Resolve` + live 200)
