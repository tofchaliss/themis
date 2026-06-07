-- Initial placeholder migration; expanded in task group 3.

CREATE TABLE IF NOT EXISTS themis_bootstrap (
    id INT PRIMARY KEY DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
