# Zeal Auth

Centralized SSO + OAuth2/OIDC provider for ZealHaven products. Issues JWT tokens, brokers Google/GitHub login, and provides shared sessions across all apps.

## Stack

- **Go** + [fosite](https://github.com/ory/fosite) (OAuth2/OIDC)
- **Postgres 18** — users, clients, tokens
- **Redis 8** — sessions, revocation
- **Docker Compose** — local dev

## Quick start

```bash
# 1. Start infra
cp .env.example .env
just up

# 2. Run migrations
just migrate-up

# 3. Start server
just dev
```

Server runs at `http://localhost:8080`.

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | /signup | Email + password registration |
| POST | /login | Email + password login |
| GET | /verify | Email verification |
| POST | /forgot-password | Request reset link |
| POST | /reset-password | Set new password |
| GET | /authorize | OAuth2 Authorization Code + PKCE |
| POST | /token | Exchange code or refresh |
| GET | /userinfo | JWT claims for access token |
| GET | /.well-known/openid-configuration | OIDC discovery |
| GET | /jwks.json | Signing keys |
| GET | /logout | Clear session |
| GET | /oauth/google | Google login |
| GET | /oauth/github | GitHub login |
| POST | /login/totp | TOTP / recovery-code step-up (5.6) |
| POST | /consent | Scope approval (5.10) |
| POST | /register | Dynamic Client Registration (5.15) |
| GET/POST | /admin, /admin/users, /admin/clients, /admin/webhooks | Admin dashboard (5.1–5.5) |
| GET/POST | /portal | Developer self-service portal (5.14) |
| GET | /profile | Profile + sessions + password (5.7/5.9) |

## Testing

```bash
just test            # unit tests
just test-integration  # full E2E against real DB + Redis
just test-cover      # coverage report
```

## Project structure

```
cmd/server/       Entry point
internal/
  config/         Environment config
  db/             Database pool
  handler/        HTTP handlers + templates
  model/          Data types
  repository/     DB queries
  service/        Business logic
  storage/        fosite storage adapter
migrations/       SQL migrations
templates/        HTML templates
docs/
  specs/          Feature specs
  plans/          Implementation plans
  references/     Brainstorm artifacts
```

## License

MIT
