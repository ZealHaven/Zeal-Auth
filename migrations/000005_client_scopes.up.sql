-- Spec 5.10: per-client allowed scopes (scope definitions per product).
-- Requested scopes outside this list are rejected by fosite before consent.
ALTER TABLE auth.clients
    ADD COLUMN IF NOT EXISTS scopes TEXT[] NOT NULL DEFAULT '{openid,profile,email}';
