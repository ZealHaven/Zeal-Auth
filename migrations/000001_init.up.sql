CREATE SCHEMA IF NOT EXISTS auth;

-- Users
CREATE TABLE auth.users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT,                          -- nullable: social-only users
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Federated identities
CREATE TABLE auth.federated_identities (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    provider          TEXT NOT NULL,             -- "google", "github"
    provider_user_id  TEXT NOT NULL,             -- IdP's sub claim
    email_at_provider TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider, provider_user_id)
);

-- Email verification tokens
CREATE TABLE auth.email_verification_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,                    -- SHA-256 of raw token
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,                      -- single-use
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Password reset tokens
CREATE TABLE auth.password_reset_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,             -- ≤ 60 min
    used_at    TIMESTAMPTZ,                      -- single-use
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Clients
CREATE TABLE auth.clients (
    id                TEXT PRIMARY KEY,           -- the client_id
    client_secret_hash TEXT NOT NULL,
    name              TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'active', -- 'active' | 'disabled'
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Client redirect URIs
CREATE TABLE auth.client_redirect_uris (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id    TEXT NOT NULL REFERENCES auth.clients(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL                    -- exact match only
);

-- Authorization codes
CREATE TABLE auth.authorization_codes (
    code_hash              TEXT PRIMARY KEY,      -- SHA-256
    client_id              TEXT NOT NULL REFERENCES auth.clients(id),
    user_id                UUID NOT NULL REFERENCES auth.users(id),
    redirect_uri           TEXT NOT NULL,
    code_challenge         TEXT NOT NULL,
    code_challenge_method  TEXT NOT NULL DEFAULT 'S256',
    scope                  TEXT,
    expires_at             TIMESTAMPTZ NOT NULL,
    used_at                TIMESTAMPTZ,           -- single-use
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Refresh tokens
CREATE TABLE auth.refresh_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash      TEXT NOT NULL UNIQUE,
    family_id       UUID NOT NULL,                -- groups rotations for theft detection
    user_id         UUID NOT NULL REFERENCES auth.users(id),
    client_id       TEXT NOT NULL REFERENCES auth.clients(id),
    scope           TEXT,
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    replaced_by_id  UUID REFERENCES auth.refresh_tokens(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Signing keys
CREATE TABLE auth.signing_keys (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kid                   TEXT NOT NULL UNIQUE,
    algorithm             TEXT NOT NULL DEFAULT 'RS256',
    public_key            TEXT NOT NULL,          -- PEM
    private_key_encrypted TEXT NOT NULL,           -- encrypted at rest
    status                TEXT NOT NULL DEFAULT 'active', -- 'active' | 'retiring' | 'retired'
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at            TIMESTAMPTZ
);

-- Indexes
CREATE INDEX idx_federated_identities_user_id ON auth.federated_identities(user_id);
CREATE INDEX idx_email_verification_tokens_user_id ON auth.email_verification_tokens(user_id);
CREATE INDEX idx_password_reset_tokens_user_id ON auth.password_reset_tokens(user_id);
CREATE INDEX idx_authorization_codes_client_id ON auth.authorization_codes(client_id);
CREATE INDEX idx_authorization_codes_user_id ON auth.authorization_codes(user_id);
CREATE INDEX idx_refresh_tokens_user_id ON auth.refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_family_id ON auth.refresh_tokens(family_id);
CREATE INDEX idx_client_redirect_uris_client_id ON auth.client_redirect_uris(client_id);
