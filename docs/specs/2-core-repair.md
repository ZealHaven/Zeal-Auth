# Auth Platform — Iteration 2: Core Repair (Phase A)

**Goal:** Make the token-issuing path actually work. Blocking for all other phases.

**Status:** ✅ Complete (2026-10-07) — 2.9 partial (see note)
**Depends on:** 1-mvp.md

Legend: ✅ done · ⚠️ partial · ❌ not done

---

## 1. Scope

| # | Item | Detail |
|---|------|--------|
| ✅ 2.1 | Wire Postgres fosite storage | Replace `storage.NewMemoryStore()` (`internal/handler/fosite_server.go:60`) with `storage.NewFositeStorage(pool)` (`internal/storage/fosite.go:93`). Codes, refresh tokens, PKCE, OIDC sessions persist in Postgres; `GetClient` reads client registry written by `/admin/clients`. |
| ✅ 2.2 | Fix Redis client | `cmd/server/main.go:51` passes URL as `Addr` — go-redis v9 needs `redis.ParseURL`. Fix construction; keep `REDIS_URL=redis://…` format in config. |
| ✅ 2.3 | Stop swallowing session errors | `internal/handler/auth_handler.go:117`, `internal/handler/broker_handler.go:79` ignore session Create errors → silent no-cookie. Surface as 500. |
| ✅ 2.4 | Email delivery | SMTP implementation behind config (`SMTP_HOST/PORT/USER/PASSWORD/FROM`), `EMAIL_DRIVER=log\|smtp`. Dev default = log (current behavior). *(smtp path code-complete, not yet exercised against a live SMTP server)* |
| ✅ 2.5 | Auth-gate client registry | `POST /admin/clients` (`handler.go:78`) is unauthenticated. Require admin secret header or admin session. → `X-Admin-Token` vs `ADMIN_TOKEN`, constant-time compare, fail-closed when unset. |
| ✅ 2.6 | Fix discovery doc | `/revoke` advertised but no route → registered `POST /revoke` + `POST /introspect` (fosite handlers existed, HTTP routes were missing); discovery also advertises per-endpoint auth methods. |
| ✅ 2.7 | Finish social login | `BeginLink`/`CompleteLink` service methods + `link_token` form flow calls `LinkIdentity`; broker callback redirects to `returnTo` (no more raw JSON). |
| ✅ 2.8 | Secrets hygiene | `FOSITE_GLOBAL_SECRET` + `ADMIN_TOKEN` in `.env.example` (≥32 bytes); `APP_ENV=prod` fail-fast boot on missing/weak `FOSITE_GLOBAL_SECRET`, `KEY_ENCRYPTION_KEY` (64 hex), `ADMIN_TOKEN`. Dev fallback kept for dev only. |
| ⚠️ 2.9 | Fix test rot | ✅ `config_test.go` port fixed · ✅ tests moved to dedicated `auth_test` DB (`internal/db/testing.go`) — no more `DROP SCHEMA` on dev DB · ✅ `*.test`/`test-results/` gitignored, junk deleted · ❌ "skip cleanly if pg down" NOT done — TestMains still panic when Postgres is down. |
| ✅ 2.10 | Happy-path OAuth integration test | `TestE2E_AuthorizeCodeFlow_HappyPath`: login → authorize → exchange → userinfo → refresh rotation → replay rejection. Smoke-verified across server restart (Postgres persistence). |

## 2. Acceptance Criteria

- ✅ **AC-2-1** Registered client (via `/admin/clients`) → `/authorize` succeeds, code returned.
- ✅ **AC-2-2** Code + `code_verifier` at `/token` → access + ID + refresh tokens issued; server restart does not invalidate them (Postgres-backed).
- ✅ **AC-2-3** `grant_type=refresh_token` rotates; old refresh unusable after rotation.
- ✅ **AC-2-4** Password reset revokes refresh tokens fosite actually issued — `TestResetPassword_RevokesFositeTokens` asserts user's tokens deleted + other users' survive.
- ✅ **AC-2-5** With default `.env.example`, login sets `sid` cookie (Redis dial works).
- ✅ **AC-2-6** Session Create failure → `500`, never silent success without cookie.
- ⚠️ **AC-2-7** `EMAIL_DRIVER=smtp` sends real mail; `log` keeps current behavior — `log` verified live; `smtp` implementation + config fail-fast done, live-server verification → **spec 4 (4.11)**.
- ✅ **AC-2-8** `POST /admin/clients` without credentials → `401`.
- ✅ **AC-2-9** Discovery document lists only routes that exist.
- ✅ **AC-2-10** Google/GitHub: callback → redirect to originating app with session; existing email + no link → link prompt that actually links.
- ✅ **AC-2-11** Boot with unset `FOSITE_GLOBAL_SECRET` in prod mode → fail fast (no hardcoded fallback).
- ⚠️ **AC-2-12** `just test` green ✅ (all packages pass on `auth_test` DB); pg-down graceful skip → **spec 3 (3.8)**.
