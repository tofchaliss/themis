-- Release-scoped VEX rollup publications (EDR-COMMUNICATION-01 D13, COMM-VEX-1).
--
-- A rollup is deliberately its OWN table, not a publications row: the Publication record is
-- Position-anchored (one stance, position_version, finding lineage — all NOT NULL by meaning,
-- not just by schema), and a rollup is a materialized POSTURE snapshot with no single stance.
--
-- input_set is the recorded D13.2 snapshot ledger — the finding list with each one's position
-- version and annotation fingerprint — which is what makes staleness EXACTLY computable
-- (stale <=> the current posture's inputs differ). The payload is the rendered document;
-- unlike per-Finding publications it is NOT prunable/regenerable-on-demand, because
-- regeneration needs the recorded as-of and the exact input posture, which only the record
-- itself holds. Delivery-channel integration and rollup outbox events are the recorded
-- follow-up (COMM-VEX-1 tasks), so no delivery columns yet.
CREATE TABLE IF NOT EXISTS release_rollups (
    id                 TEXT PRIMARY KEY,
    release_id         TEXT NOT NULL,
    product_purl       TEXT NOT NULL,
    format             TEXT NOT NULL,
    audience           TEXT NOT NULL DEFAULT '',
    payload            BYTEA NOT NULL,
    input_set          JSONB NOT NULL,
    as_of              TIMESTAMPTZ NOT NULL,
    statements         INT NOT NULL,
    withdrawn_excluded INT NOT NULL DEFAULT 0,
    supersedes_id      TEXT NOT NULL DEFAULT '',
    superseded_by      TEXT NOT NULL DEFAULT '',
    version            INT NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_release_rollups_release ON release_rollups (release_id, created_at DESC);
