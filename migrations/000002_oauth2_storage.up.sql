-- fosite request storage (token ↔ request mapping)
CREATE TABLE auth.fosite_requests (
    key        TEXT PRIMARY KEY,          -- SHA-256(code) for auth codes, HMAC signature for tokens
    data       JSONB NOT NULL,            -- serialized fosite.Request
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- access token storage (JWT tokens stored for revocation support)
CREATE TABLE auth.access_tokens (
    signature   TEXT PRIMARY KEY,         -- HMAC signature from JWT
    request_id  TEXT NOT NULL,            -- fosite Request ID
    expires_at  TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_access_tokens_request_id ON auth.access_tokens(request_id);

-- JTI tracking for client_assertion JWTs
CREATE TABLE auth.client_assertions (
    jti        TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);
