CREATE TABLE system_state (
    key TEXT PRIMARY KEY,
    value TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO system_state (key, value)
VALUES ('cve_watch_last_success', NOW());
