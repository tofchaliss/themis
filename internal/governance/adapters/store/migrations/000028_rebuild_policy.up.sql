-- EDR-REBUILD-01 step R1 (D2, D9, D11 item 4): the rebuild policy record and its history.
--
-- rebuild_policies holds the policy IN FORCE, one row per scope. Step R1 writes the
-- installation scope only (scope_kind 'installation', scope_id ''); the two columns exist so
-- that Product and Release policies (step R1a) need no second table. No row for the
-- installation means the shipped defaults of D2 are in force, at version 0.
--
-- version counts the changes of one scope's policy from 1. It is carried on every rebuild
-- request (D11 item 4), and the approval of D46 locks this row while it checks the mode.
CREATE TABLE IF NOT EXISTS rebuild_policies (
    scope_kind            TEXT NOT NULL,
    scope_id              TEXT NOT NULL DEFAULT '',
    version               INT NOT NULL CHECK (version >= 1),
    fix_required          BOOLEAN NOT NULL,
    severity_floor        TEXT NOT NULL CHECK (severity_floor IN ('critical', 'high', 'medium', 'low')),
    count_known_exploited BOOLEAN NOT NULL,
    skip_decided          BOOLEAN NOT NULL,
    carrier_only          BOOLEAN NOT NULL,
    cool_down_seconds     BIGINT NOT NULL CHECK (cool_down_seconds >= 0),
    mode                  TEXT NOT NULL CHECK (mode IN ('off', 'ask', 'auto')),
    updated_at            TIMESTAMPTZ NOT NULL,
    updated_by            TEXT NOT NULL CHECK (updated_by <> ''),
    PRIMARY KEY (scope_kind, scope_id)
);

-- Every version a scope's policy ever had, append-only. A policy that can start builds needs a
-- name and a time on every change (D9); the row in rebuild_policies alone would lose them.
CREATE TABLE IF NOT EXISTS rebuild_policy_history (
    scope_kind            TEXT NOT NULL,
    scope_id              TEXT NOT NULL DEFAULT '',
    version               INT NOT NULL,
    fix_required          BOOLEAN NOT NULL,
    severity_floor        TEXT NOT NULL,
    count_known_exploited BOOLEAN NOT NULL,
    skip_decided          BOOLEAN NOT NULL,
    carrier_only          BOOLEAN NOT NULL,
    cool_down_seconds     BIGINT NOT NULL,
    mode                  TEXT NOT NULL,
    updated_at            TIMESTAMPTZ NOT NULL,
    updated_by            TEXT NOT NULL,
    PRIMARY KEY (scope_kind, scope_id, version)
);
