# Plan 1-2: Signing Keys Management

**Spec:** `docs/specs/1-mvp.md §5 (signing_keys table), AC-OIDC-4`
**Depends on:** 1-0, 1-1
**Estimated scope:** 1 Go file, ~100 lines

---

## Context

The auth platform signs JWTs with RS256. We need key generation, storage, loading, and rotation support. Keys are stored encrypted in the `auth.signing_keys` table.

## Task

### 1. Key service (`internal/service/keys.go`)

Functions:
- `GenerateKeyPair(kid string) (*KeyPair, error)` — generate RSA 2048-bit key pair, return PEM-encoded public + encrypted private key
- `GetActiveKey() (*KeyPair, error)` — query `auth.signing_keys WHERE status = 'active'`, decrypt private key
- `GetAllActiveKeys() ([]*KeyPair, error)` — for JWKS: return all keys with status `active` or `retiring` (rotation window)
- `RotateKey() error` — mark current active as `retiring`, generate new key as `active`
- `RetireOldKeys() error` — mark `retiring` keys older than rotation window as `retired`

### 2. Key encryption

For MVP: use a static encryption key from config (`KEY_ENCRYPTION_KEY` env var, 32 bytes hex). Use `crypto/aes` GCM to encrypt/decrypt the private key PEM at rest.

```go
func EncryptPrivateKey(privPEM []byte, key []byte) ([]byte, error)
func DecryptPrivateKey(encPEM []byte, key []byte) ([]byte, error)
```

### 3. Initial key generation

On first startup (no active key in DB):
- Generate key pair with `kid` from config (`JWT_KID`, default `"key-1"`)
- Store in `auth.signing_keys`
- Log that initial key was created

### 4. Config additions

Add to `internal/config/config.go`:
```
KEY_ENCRYPTION_KEY = ""  # hex-encoded 32-byte key, REQUIRED
JWT_KID            = "key-1"
```

## Automatic Testing

### Test file: `internal/service/keys_test.go`
```go
func TestGenerateKeyPair_ReturnsRSA2048(t *testing.T)  // key is RSA, 2048-bit
func TestEncryptDecrypt_Roundtrip(t *testing.T)        // encrypt then decrypt recovers original PEM
func TestEncryptDecrypt_WrongKey_Fails(t *testing.T)   // wrong decryption key returns error
func TestEnsureInitialKey_CreatesOnFreshDB(t *testing.T) // no key → creates one
func TestEnsureInitialKey_NoopIfExists(t *testing.T)   // key exists → no duplicate created
func TestGetActiveKey_ReturnsDecryptableKey(t *testing.T)
func TestGetAllActiveKeys_IncludesActiveAndRetiring(t *testing.T)
func TestRotateKey_DemotesOld_CreatesNew(t *testing.T) // old=retiring, new=active
func TestRetireOldKeys_MarksRetired(t *testing.T)
func TestPrivateKey_NeverStoredPlaintext(t *testing.T)  // raw SQL check: private_key_encrypted != PEM header
```

### Verification command
```bash
go test ./internal/service/ -run TestKey -v -count=1
```

## Acceptance Criteria

- [ ] On fresh DB, startup generates an RSA 2048 key pair and stores it
- [ ] `GetActiveKey()` returns the key, private key decrypts correctly
- [ ] `GetAllActiveKeys()` returns both `active` and `retiring` keys (for JWKS rotation)
- [ ] `RotateKey()` demotes current key, generates new one
- [ ] Private key is never stored in plaintext
- [ ] `jwk.FromRSAPrivateKey` (fosite) can load the key for JWT signing
- [ ] `go test ./internal/service/ -run TestKey -v` passes — all key operations verified

## Files touched

- `internal/service/keys.go`
- `internal/service/keys_test.go`
- `internal/config/config.go` (add 2 env vars)
- `cmd/server/main.go` (call `EnsureInitialKey` on startup)
