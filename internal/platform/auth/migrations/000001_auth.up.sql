-- Auth schema — the shared `auth` database (EDR-SECURITY-01 D2). A single api_keys table
-- backing inbound API-key authentication for every context service. This DB carries
-- infrastructure identity, not business state, so it creates no cross-context business join
-- (same justification as the platform `bus` database).

CREATE TABLE IF NOT EXISTS api_keys (
    -- Opaque key id; also the auditable principal id (CON-0016).
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    -- bcrypt hash of the raw token; the token itself is never stored (D3).
    key_hash   TEXT NOT NULL,
    -- Granted scopes: 'admin' | 'read' | 'product:<id>' (D4).
    scopes     TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Optional expiry; NULL = no expiry.
    expires_at TIMESTAMPTZ,
    -- Set on revoke; NULL = active.
    revoked_at TIMESTAMPTZ
);

-- The middleware scans only active (non-revoked) keys on each request.
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys (id) WHERE revoked_at IS NULL;
