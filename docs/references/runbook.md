# Runbooks (Prod Hardening — Spec 4)

## TLS / Cloudflare Tunnel (4.3, AC-4-7)

The origin server speaks **plain HTTP** on `127.0.0.1:8080`; TLS terminates at
Cloudflare. Cloudflared sets `X-Forwarded-Proto: https`, which the server
trusts (`TrustForwardedProto` middleware, `internal/handler/middleware.go`) so
scheme-dependent behavior (secure-cookie decisions, redirects) sees the
original scheme. The `sid` cookie is always `Secure`+`HttpOnly`+`SameSite=Lax`
and round-trips through the tunnel.

`cloudflared` config (`~/.cloudflared/config.yml`):

```yaml
tunnel: <TUNNEL_UUID>
credentials-file: /root/.cloudflared/<TUNNEL_UUID>.json

ingress:
  - hostname: auth.yourdomain.com
    service: http://127.0.0.1:8080
  - service: http_status:404
```

DNS: `CNAME auth.yourdomain.com → <TUNNEL_UUID>.cfargotunnel.com`.

Then:

```bash
cloudflared tunnel route dns <TUNNEL_UUID> auth.yourdomain.com
cloudflared tunnel run <TUNNEL_UUID>
```

`COOKIE_DOMAIN`, `PUBLIC_URL`, and Google/GitHub redirect URIs must all use
`https://auth.yourdomain.com`.

## Backups (4.7, AC-4-5)

Daily `pg_dump -Fc` runs in the `backup` service (profile `backup`):

```bash
docker compose -f docker-compose.prod.yml --profile backup up -d backup
```

Dumps land in `./backups/auth-YYYYMMDD-HHMMSS.dump`; files older than
`BACKUP_RETENTION_DAYS` (default 14) are deleted. One-off backup: `just backup`.

### Restore

1. Stop the app: `docker compose -f docker-compose.prod.yml stop app`
2. Restore: `just restore backups/auth-YYYYMMDD-HHMMSS.dump`
   (`pg_restore --clean --if-exists` — drops replaced objects first)
3. Start the app: `docker compose -f docker-compose.prod.yml up -d --wait app`
4. Verify: log in with an existing account; `GET /health` returns `ok`.

## Migrations (4.8)

Migrations run as a deploy step — never by the app process:

```bash
docker compose -f docker-compose.prod.yml --profile deploy run --rm migrate
```

or `just prod-up` (migrate, then compose `up --wait`). AC-4-6: the app must
start only after `migrate up` exits 0.

## Key rotation (4.6)

The app rotates signing keys on a ticker (`KEY_ROTATION_INTERVAL`, default
`168h`): the old active key is demoted to `retiring` (stays in JWKS for
`KEY_RETIRE_WINDOW`) and a new kid becomes active. Retire via the same loop.
Manual trigger in a psql/gopsql session:

```sql
-- new active key + demote old (normally done by RotateKey):
-- use the admin flow or wait for the ticker; verify via GET /jwks.json —
-- both kids must be present during the overlap window.
```

## Prod secrets (4.4, AC-4-2)

Boot fails (non-zero exit, listed `config error:` lines) when `APP_ENV=prod`
and any of: `FOSITE_GLOBAL_SECRET` <32 bytes or dev placeholder,
`KEY_ENCRYPTION_KEY` missing/placeholder/non-64-hex, `ADMIN_TOKEN` empty,
`COOKIE_DOMAIN` placeholder, `EMAIL_DRIVER=smtp` with missing/placeholder
SMTP settings, or a Google/GitHub client ID without its secret.

Generate:

```bash
openssl rand -base64 48   # FOSITE_GLOBAL_SECRET
openssl rand -hex 32      # KEY_ENCRYPTION_KEY
openssl rand -hex 24      # ADMIN_TOKEN
```

## SMTP verification (4.11, AC-4-8)

`EMAIL_DRIVER=smtp` is exercised against a real SMTP server (Mailpit/Mailhog
in staging, provider in prod):

1. `docker run -d -p 1025:1025 -p 8025:8025 axllent/mailpit`
2. `.env`: `EMAIL_DRIVER=smtp`, `SMTP_HOST=localhost`, `SMTP_PORT=1025`,
   `EMAIL_FROM=Zeal Auth <no-reply@test.local>`
3. Restart server → sign up a new address → open `http://localhost:8025` →
   "Verify your email" message contains a working `/verify?token=` link.
4. Forgot password → "Reset your password" message with working
   `/reset-password?token=` link. Both flows confirmed 2026-10-10 (AC-2-7
   closed).
