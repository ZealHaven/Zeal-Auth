DROP TABLE IF EXISTS auth.role_scopes;
DROP TABLE IF EXISTS auth.webhooks;
DROP TABLE IF EXISTS auth.mfa_recovery_codes;
DROP TABLE IF EXISTS auth.client_post_logout_uris;
DROP TABLE IF EXISTS auth.audit_log;

ALTER TABLE auth.clients DROP COLUMN IF EXISTS rp_logout_allowed;
ALTER TABLE auth.clients DROP COLUMN IF EXISTS owner_id;

ALTER TABLE auth.users DROP COLUMN IF EXISTS totp_enabled;
ALTER TABLE auth.users DROP COLUMN IF EXISTS totp_secret;
ALTER TABLE auth.users DROP COLUMN IF EXISTS disabled_at;
ALTER TABLE auth.users DROP COLUMN IF EXISTS role;
