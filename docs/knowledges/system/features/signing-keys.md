---
feature: signing-keys
status: delivered
specs: [docs/specs/1-mvp.md]
plans: [docs/plans/1-2-signing-keys.md]
commits: (see git log)
---

# Signing Keys Management

## What Was Built

RSA 2048-bit key pair generation, encrypted storage, retrieval, rotation, and retirement for JWT signing. Private keys are encrypted with AES-GCM (base64-encoded for DB storage) using a static 32-byte hex key from config. On fresh DB startup, an initial key pair is auto-generated.

## Position in Auth Platform

Signing keys sit at the foundation of the token system — every JWT issued by the auth server is signed with the active key's private key. The JWKS endpoint exposes public keys from `active` and `retiring` keys, enabling relying parties to verify tokens without calling the auth server.

## Data Model

### auth.signing_keys

| Column | Type | Notes |
|--------|------|-------|
| id | uuid PK | auto-generated |
| kid | text UK | key identifier (e.g. "key-1") |
| algorithm | text | always "RS256" |
| public_key | text | PEM-encoded |
| private_key_encrypted | text | AES-GCM encrypted, base64-encoded |
| status | text | "active", "retiring", "retired" |
| created_at | timestamptz | |
| rotated_at | timestamptz | nullable, set when demoted to retiring |

Key lifecycle: `active` → `retiring` (on rotate) → `retired` (after rotation window expires).

## Architecture

### Files

| File | Purpose |
|------|---------|
| `internal/service/keys.go` | Core key management: generate, encrypt/decrypt, CRUD, rotate, retire |
| `internal/service/keys_test.go` | 10 tests — unit (encrypt roundtrip, wrong key) + integration (DB operations) |
| `internal/config/config.go` | Added `KeyEncryptionKey` field |
| `cmd/server/main.go` | Calls `EnsureInitialKey()` on startup |

### Key Functions

| Function | Purpose |
|----------|---------|
| `GenerateKeyPair` | RSA 2048 gen, encrypt private, store in DB |
| `GetActiveKey` | Query active key, decrypt private for signing |
| `GetAllActiveKeys` | Returns active + retiring keys for JWKS |
| `RotateKey` | Demote current → retiring, generate new → active |
| `RetireOldKeys` | Mark old retiring keys as retired past rotation window |
| `EnsureInitialKey` | Idempotent first-startup key generation |
| `EncryptPrivateKey` / `DecryptPrivateKey` | AES-GCM with random nonce |
| `ParseRSAPrivateKey` | PEM → `*rsa.PrivateKey` for fosite JWT signing |

### Config

| Env Var | Default | Purpose |
|---------|---------|---------|
| `KEY_ENCRYPTION_KEY` | "" (required) | 64-char hex string (32 bytes) for AES-GCM |
| `JWT_KID` | "key-1" | Key identifier for initial key |

## Known Issues / Deferred Work

- `KEY_ENCRYPTION_KEY` is a static env var — no key rotation for the encryption key itself
- `ParseRSAPrivateKey` added but not yet wired to fosite JWT signer (plan 1-3)
- `RetireOldKeys` has no scheduler — needs a cron/ticker to call it periodically
- `go test ./...` requires `-p 1` because `keys_test` and `migration_test` share the same DB and both manipulate schema in `TestMain`
