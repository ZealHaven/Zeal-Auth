# Auth Platform — Iteration 3: First Product Integration (Phase B)

**Goal:** First real product logs in via Zeal Auth in dev. Repeatable recipe for every future product.

**Status:** Not started
**Depends on:** 2-core-repair.md

---

## 1. Scope

| # | Item | Detail |
|---|------|--------|
| 3.1 | Client seeding | `just seed-client` (or script) registers one OAuth client per product: id, secret (shown once), exact redirect URIs. Dev-seeded clients store secret hashed per `1-mvp.md` §2. |
| 3.2 | Integration recipe doc | `docs/integrating.md`: authorize redirect → code exchange → JWKS verify → refresh. ~30 lines per product, no SDK required. Include Go snippet using `golang-jwt` + JWKS fetch. |
| 3.3 | Dev ergonomics | `localhost` http redirect URIs allowed in dev (`APP_ENV=dev`); `EMAIL_DRIVER=log` default; seed script creates test user(s). |
| 3.4 | Multi-client SSO check | Two seeded clients; login via client 1 → authorize client 2 → no login screen (silent auth, `1-mvp.md` Flow C). |
| 3.5 | First consumer integration | Wire one real Zeal product (or a minimal reference client app) end-to-end in dev. |
| 3.6 | Logout revokes refresh tokens | `/logout` clears session only — refresh tokens issued before logout stay redeemable (fails AC-TOKEN-5). Revoke user's fosite tokens on logout (same `fosite_requests` subject delete as password reset). |
| 3.7 | JWKS local-validation assertions | Reference client (3.5) must verify ID/access token signatures against `/jwks.json` and reject a tampered signature — closes AC-OIDC-3 + AC-TOKEN-1. |
| 3.8 | Graceful skip when pg down | TestMains panic when Postgres is unreachable (`db.EnsureTestDatabase` fails) → skip with clear message instead, closing AC-2-12. |
| 3.9 | Screen URL conformance | `1-mvp.md` §5 specifies `/signup/check-email` and `/forgot-password/check-email`; implementation serves a single `GET /check-email`. Either add the two routes (redirect/alias) or update the spec tables to the real URL. |

## 2. Acceptance Criteria

- **AC-3-1** `just seed-client <name> <redirect-uri>` → client usable at `/authorize` immediately.
- **AC-3-2** Reference client completes auth-code + PKCE flow against local server, verifies ID token via JWKS.
- **AC-3-3** Silent SSO: session from client 1 → client 2 authorize with no login prompt.
- **AC-3-4** New dev machine: `cp .env.example .env && just up && just migrate-up && just seed && just dev` → working login in <10 min following `docs/integrating.md` only.
- **AC-3-5** Secrets never logged or re-displayable after creation.
- **AC-3-6** Logout → previously issued refresh token rejected at `/token` (closes AC-TOKEN-5).
- **AC-3-7** Reference client verifies ID token signature against JWKS; token with flipped signature claim fails verification (closes AC-OIDC-3, AC-TOKEN-1).
- **AC-3-8** `go test ./...` with Postgres stopped → packages report SKIP (not panic/non-zero), closing AC-2-12.
- **AC-3-9** Both `/signup/check-email` and `/forgot-password/check-email` URLs from `1-mvp.md` §5 resolve (or spec table updated to match reality).
