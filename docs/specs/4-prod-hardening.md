# Auth Platform — Iteration 4: Production Hardening (Phase C)

**Goal:** Zeal Auth runs as the trusted IdP in prod — secure defaults, fail-fast config, recoverable data.

**Status:** ✅ Complete (2026-10-10) — all ACs verified against live prod stack (AC-4-8 closes AC-2-7)
**Depends on:** 3-first-integration.md

---

## 1. Scope

| # | Item | Detail |
|---|------|--------|
| 4.1 | App container | Dockerfile for auth-server; compose prod override: app service + healthchecks (pg, redis, app), no dev creds, no published pg/redis ports. |
| 4.2 | Health | `/health` covers DB only → add Redis ping; healthcheck in orchestrator. |
| 4.3 | TLS / proxy | Server stays plain HTTP behind Cloudflare Tunnel (per `1-mvp.md`); trust `X-Forwarded-Proto` so `Secure` cookies work; document tunnel config for `auth.<domain>`. |
| 4.4 | Secrets management | Prod: `FOSITE_GLOBAL_SECRET`, 64-hex `KEY_ENCRYPTION_KEY`, SMTP creds, Google/GitHub secrets from env/secret manager. Boot fails if any required secret missing or dev placeholder detected (`main.go:43`). `APP_ENV=prod` gates. |
| 4.5 | Rate limiting + lockout | Login/signup/reset/token endpoints: per-IP + per-account throttling; brute-force lockout with backoff (spec deferred this — prod can't). |
| 4.6 | Automated key rotation | Cron/cron-job calls existing `KeyService.RotateKey` + `RetireOldKeys` (`internal/service/keys.go:170-190`, currently no callers). JWKS publishes active + retiring during overlap (`AC-OIDC-4`). |
| 4.7 | Postgres backups | `pg_dump` cron volume/strategy; restore runbook. |
| 4.8 | Migrations in deploy | `migrate up` as deploy step (job/init container), not manual `just`. |
| 4.9 | Middleware baseline | Request logging, panic recovery, security headers on bare `ServeMux`. |
| 4.10 | Session cookie audit | `SameSite=Lax` OK for MVP cross-site redirects; verify + document choice; `Secure` enforced in prod. |
| 4.11 | Live SMTP verification | `EMAIL_DRIVER=smtp` implementation is code-complete but never exercised against a real server (AC-2-7). Verify against prod SMTP (or Mailpit/Mailhog in staging): signup → verification mail received; forgot-password → reset mail received. |

## 2. Acceptance Criteria

- **AC-4-1** `docker compose -f docker-compose.prod.yml up` boots full stack healthy; pg/redis not reachable from host.
- **AC-4-2** Boot with missing/placeholder secrets in `APP_ENV=prod` → process exits non-zero, clear error.
- **AC-4-3** 6 failed logins in 10 min → account/IP throttled; legitimate login works after window.
- **AC-4-4** Key rotation ran: old kid still in JWKS, new kid active, tokens signed with old kid still verify during overlap.
- **AC-4-5** Backup taken → wipe DB → restore → login works.
- **AC-4-6** Deploy pipeline runs migrations automatically; app starts only after `migrate up` succeeds.
- **AC-4-7** Behind tunnel with TLS, `sid` cookie has `Secure` and round-trips.
- **AC-4-8** `EMAIL_DRIVER=smtp` delivers verification + reset emails through the configured SMTP server (closes AC-2-7).
