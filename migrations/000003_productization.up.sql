-- Spec 5: productization schema
-- 5.1 admin roles · 5.5 audit · 5.3 post-logout URIs · 5.6 TOTP
-- 5.13 webhooks · 5.14 developer portal · 5.16 RBAC

-- 5.1 + 5.16: role on users ('user' | 'admin'); role claims feed token scopes.
ALTER TABLE auth.users
    ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user',
    ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMPTZ;

-- 5.6: TOTP MFA
ALTER TABLE auth.users
    ADD COLUMN IF NOT EXISTS totp_secret TEXT,           -- base32, NULL = MFA off
    ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE;

-- 5.5: audit trail (DB first; Kafka deferred). actor = user uuid or 'system'/'admin-token'.
CREATE TABLE IF NOT EXISTS auth.audit_log (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor      TEXT NOT NULL,                 -- user_id | 'system' | 'admin-token'
    action     TEXT NOT NULL,                 -- e.g. login, signup, reset, client.create
    target     TEXT,                          -- affected resource (user_id, client_id)
    detail     JSONB,
    ip         TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON auth.audit_log(actor);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON auth.audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_created ON auth.audit_log(created_at);

-- 5.3: registered post-logout redirect URIs (exact-match, AC-5-6)
CREATE TABLE IF NOT EXISTS auth.client_post_logout_uris (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id    TEXT NOT NULL REFERENCES auth.clients(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    UNIQUE (client_id, redirect_uri)
);

-- 5.6: single-use TOTP recovery codes (hashed)
CREATE TABLE IF NOT EXISTS auth.mfa_recovery_codes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_user ON auth.mfa_recovery_codes(user_id);

-- 5.13: event webhooks (HMAC-signed)
CREATE TABLE IF NOT EXISTS auth.webhooks (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url        TEXT NOT NULL,
    secret     TEXT NOT NULL,                 -- HMAC signing secret
    events     TEXT[] NOT NULL DEFAULT '{}',  -- e.g. {user.created,user.disabled}
    status     TEXT NOT NULL DEFAULT 'active',-- 'active' | 'disabled'
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 5.14: developer self-service portal (owner → clients). clients.id is the client_id.
ALTER TABLE auth.clients
    ADD COLUMN IF NOT EXISTS owner_id UUID REFERENCES auth.users(id) ON DELETE SET NULL;

-- 5.16: per-role scopes granted on top of consent scopes (5.10).
-- e.g. role 'admin' → {'admin','billing:read'}.
CREATE TABLE IF NOT EXISTS auth.role_scopes (
    role  TEXT NOT NULL,
    scope TEXT NOT NULL,
    PRIMARY KEY (role, scope)
);
INSERT INTO auth.role_scopes (role, scope) VALUES
    ('admin', 'admin'),
    ('admin', 'billing:read')
ON CONFLICT DO NOTHING;

-- 5.8: allow-list of clients permitted to trigger RP-initiated logout (AC-5-6).
-- Own products seed this; third-party clients are excluded by default.
ALTER TABLE auth.clients
    ADD COLUMN IF NOT EXISTS rp_logout_allowed BOOLEAN NOT NULL DEFAULT FALSE;
