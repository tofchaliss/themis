-- Dashboard-local login users (EDR-GUI-01 D3 amendment 2026-10-12, D12).
--
-- This table lives in the shared `auth` database but is OWNED BY THE DASHBOARD, not by
-- `internal/platform/auth`: browser logins are a concern no other node has, and growing the
-- shared platform package for one consumer is how platform packages rot (D12). It therefore
-- carries its own golang-migrate bookkeeping table (`dashboard_schema_migrations`, attached by
-- cmd/dashboard's migration DSN), exactly the way Registry keeps `registry_schema_migrations`
-- while co-locating in the `evidence` database — without it, whichever binary migrated second
-- would read the other's version number and silently skip its own CREATE TABLE.
--
-- Like api_keys, this is infrastructure identity, not business state, so it creates no
-- cross-context business join.

CREATE TABLE IF NOT EXISTS dashboard_users (
    -- The login name; also the operator id stamped on decisions (EDR-GUI-01 D13), which is
    -- why the shared `admin` account puts the name `admin` on audit records.
    username            TEXT PRIMARY KEY,
    -- bcrypt hash of the password; the password itself is never stored and never logged.
    password_hash       BYTEA NOT NULL,
    -- TRUE while the row still holds the shipped default, so the GUI can say so plainly.
    is_default_password BOOLEAN NOT NULL DEFAULT FALSE,
    -- Bumped on every password change. The dashboard captures it at login as the session's
    -- password stamp, and the D12 mutation re-verify refuses a session whose stamp no longer
    -- matches — which is how a password change ends that user's OTHER sessions.
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
