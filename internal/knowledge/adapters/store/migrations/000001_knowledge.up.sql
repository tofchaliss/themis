-- Knowledge context schema (EDR-KNOWLEDGE-01 D9): the Faultline aggregate — one card
-- per canonical CVE — with its append-only source Proposals and a materialized
-- enterprise view, plus the shared transactional outbox. The Knowledge context owns
-- its own tables (Book III §3.5), separate from every other context.

CREATE TABLE IF NOT EXISTS faultlines (
    id         TEXT PRIMARY KEY,          -- own opaque identity (never the CVE)
    cve        TEXT NOT NULL UNIQUE,      -- canonical CVE = the binding business key
    stage      TEXT NOT NULL,             -- lifecycle ladder stage
    version    INT  NOT NULL,             -- optimistic-concurrency stamp
    view       JSONB NOT NULL,            -- materialized reconciled enterprise view
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

-- Append-only source Proposals; seq is the stable append order within a card, so a
-- re-save inserts only the new tail (ON CONFLICT DO NOTHING).
CREATE TABLE IF NOT EXISTS faultline_proposals (
    faultline_id TEXT NOT NULL REFERENCES faultlines (id),
    seq          INT  NOT NULL,
    source       TEXT NOT NULL,
    observed_at  TIMESTAMPTZ NOT NULL,
    kind         TEXT NOT NULL,
    payload      JSONB NOT NULL,
    PRIMARY KEY (faultline_id, seq)
);

-- Transactional outbox (BCK-0041): a Knowledge event is written in the same local
-- transaction as the card mutation, then delivered by a background relay.
CREATE TABLE IF NOT EXISTS knowledge_outbox (
    id           TEXT PRIMARY KEY,
    faultline_id TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    payload      JSONB NOT NULL,
    occurred_at  TIMESTAMPTZ NOT NULL,
    sent_at      TIMESTAMPTZ,
    attempts     INT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_knowledge_outbox_unsent
    ON knowledge_outbox (occurred_at)
    WHERE sent_at IS NULL;

-- Correlation matches (D3): a release component that matched a card. The primary key
-- makes ComponentMatched idempotent — a re-scan of the same occurrence records no new
-- match and emits no duplicate event. "Which releases are affected by card F" is a
-- projection over these rows, never card state (D3/D10).
CREATE TABLE IF NOT EXISTS faultline_matches (
    release_id     TEXT NOT NULL,
    faultline_id   TEXT NOT NULL REFERENCES faultlines (id),
    component_purl TEXT NOT NULL,
    matched_at     TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (release_id, faultline_id, component_purl)
);

CREATE INDEX IF NOT EXISTS idx_faultline_matches_release ON faultline_matches (release_id);
CREATE INDEX IF NOT EXISTS idx_faultline_matches_faultline ON faultline_matches (faultline_id);

-- Scheduled-watch watermark (D5/D11): a single row holding the last successful poll, so
-- a restart resumes without reprocessing the world (PoC: system_state.cve_watch_last_success).
CREATE TABLE IF NOT EXISTS knowledge_watch_state (
    id           INT PRIMARY KEY,
    last_success TIMESTAMPTZ NOT NULL
);
