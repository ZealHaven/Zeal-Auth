---
feature: database-schema
status: delivered
specs: [docs/specs/1-mvp.md]
plans: [docs/plans/1-1-database-schema.md]
commits: (see git log)
---

# Database Schema

## What Was Built
Initial migration with all 9 tables for the auth platform in a separate `auth` schema. Includes users, federated identities, email/password reset tokens, OAuth clients, authorization codes, refresh tokens, and signing keys.

## Position in Auth Platform
Foundation layer — all other features (signup, login, OAuth, sessions) depend on these tables.

## Data Model

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| `auth.users` | Core user records | `id` (UUID), `email` (unique), `password_hash` (nullable), `email_verified` |
| `auth.federated_identities` | Social login links | `user_id` (FK), `provider`, `provider_user_id` — unique on (provider, provider_user_id) |
| `auth.email_verification_tokens` | Email verify flow | `user_id` (FK), `token_hash`, `expires_at`, `used_at` (single-use) |
| `auth.password_reset_tokens` | Password reset flow | `user_id` (FK), `token_hash`, `expires_at`, `used_at` (single-use) |
| `auth.clients` | OAuth2 clients | `id` (text PK = client_id), `client_secret_hash`, `status` |
| `auth.client_redirect_uris` | Allowed redirect URIs | `client_id` (FK), `redirect_uri` |
| `auth.authorization_codes` | OAuth2 auth codes | `code_hash` (PK), `client_id`/`user_id` (FK), `code_challenge`, PKCE support |
| `auth.refresh_tokens` | Token refresh + rotation | `token_hash` (unique), `family_id` (theft detection), `replaced_by_id` (rotation chain) |
| `auth.signing_keys` | JWT signing keys | `kid` (unique), `public_key`, `private_key_encrypted`, `status` (active/retiring/retired) |

## Architecture

| File | Purpose |
|------|---------|
| `migrations/000001_init.up.sql` | Creates auth schema + 9 tables + 8 indexes |
| `migrations/000001_init.down.sql` | `DROP SCHEMA auth CASCADE` |
| `migrations/migration_test.go` | 7 tests verifying schema structure via `information_schema` |

## Known Issues / Deferred Work

- **Port conflict**: `docker-compose.yml` uses port 5435 (not 5433) because 5433 is occupied by `sso2-postgres`. Update when sso2 is decommissioned.
- **schema_migrations location**: `golang-migrate` puts `schema_migrations` inside the `auth` schema (due to Postgres `search_path`). This means `migrate down` can't track completion after dropping the schema. Tests use direct SQL for down-migration verification.
- **No `x-multi-schema` support**: The pgx driver doesn't support `x-multi-schema` parameter, so schema_migrations can't be moved to `public` schema.
