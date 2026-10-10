-- Spec 5.10: remembered scope grants (consent screen skips previously granted scopes)
CREATE TABLE IF NOT EXISTS auth.scope_grants (
    client_id  TEXT NOT NULL REFERENCES auth.clients(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    scope      TEXT NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (client_id, user_id, scope)
);
