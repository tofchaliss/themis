-- Communication context schema (EDR-COMMUNICATION-01 D9): the Publication aggregate — one
-- immutable record per materialized artifact from one Enterprise Position version — with a
-- permanent lineage + a capped, regenerable payload (NULL once pruned), a mutable delivery
-- outcome, append-and-supersede links, and an optimistic version. Plus the shared
-- transactional outbox for terminal audit events, and the publishable-positions worklist
-- projection. The Communication context owns its own tables (Book III §3.5) — no sharing.

CREATE TABLE IF NOT EXISTS publications (
    id                  TEXT PRIMARY KEY,              -- own opaque identity (provenance)
    artifact_type       TEXT NOT NULL,
    stance              TEXT NOT NULL,                 -- carried verbatim from the Position (D3)
    title               TEXT NOT NULL DEFAULT '',
    summary             TEXT NOT NULL DEFAULT '',
    rationale           TEXT NOT NULL DEFAULT '',
    position_version    INT  NOT NULL,                 -- which Position version was materialized
    release_id          TEXT NOT NULL,                 -- lineage handles (CON-0016)
    finding_id          TEXT NOT NULL,
    faultline_id        TEXT NOT NULL,
    cve                 TEXT NOT NULL DEFAULT '',
    format              TEXT NOT NULL,
    audience            TEXT NOT NULL DEFAULT '',
    channel             TEXT NOT NULL DEFAULT '',
    payload             BYTEA,                          -- capped, regenerable (NULL = pruned)
    delivery_status     TEXT NOT NULL,
    delivery_attempts   INT  NOT NULL DEFAULT 0,
    delivery_last_error TEXT NOT NULL DEFAULT '',
    delivered_at        TIMESTAMPTZ,                    -- NULL until delivered
    supersedes_id       TEXT NOT NULL DEFAULT '',       -- the prior Publication this replaced
    superseded_by_id    TEXT NOT NULL DEFAULT '',       -- the newer Publication that replaced this
    version             INT  NOT NULL,                  -- optimistic-concurrency stamp
    created_at          TIMESTAMPTZ NOT NULL
);

-- "Current" published artifact for an identity tuple = the latest non-superseded row (D5).
CREATE INDEX IF NOT EXISTS idx_publications_identity
    ON publications (release_id, faultline_id, artifact_type, audience);
CREATE INDEX IF NOT EXISTS idx_publications_release ON publications (release_id);
-- Pending deliveries are the durable delivery queue (D6): the delivery worker scans them.
CREATE INDEX IF NOT EXISTS idx_publications_pending
    ON publications (created_at)
    WHERE delivery_status = 'pending';

-- Transactional outbox (BCK-0041): a terminal Communication event is written in the same
-- local transaction as its aggregate mutation, then delivered by a background relay.
CREATE TABLE IF NOT EXISTS communication_outbox (
    id             TEXT PRIMARY KEY,
    publication_id TEXT NOT NULL,
    event_type     TEXT NOT NULL,
    payload        JSONB NOT NULL,
    occurred_at    TIMESTAMPTZ NOT NULL,
    sent_at        TIMESTAMPTZ,
    attempts       INT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_communication_outbox_unsent
    ON communication_outbox (occurred_at)
    WHERE sent_at IS NULL;

-- Publishable-positions worklist projection (D4/D10): the analyst worklist of Positions
-- ready to publish or gone stale (need re-publish), one row per Finding.
CREATE TABLE IF NOT EXISTS publishable_positions (
    finding_id   TEXT PRIMARY KEY,
    release_id   TEXT NOT NULL,
    faultline_id TEXT NOT NULL,
    cve          TEXT NOT NULL DEFAULT '',
    version      INT  NOT NULL,
    stance       TEXT NOT NULL,
    stale        BOOLEAN NOT NULL DEFAULT false,
    updated_at   TIMESTAMPTZ NOT NULL
);
