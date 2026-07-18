-- Governance context schema (EDR-GOVERNANCE-01 D9): the Finding aggregate — one record
-- per (Release, Faultline) — with its matched-component content, append-only Governance
-- Proposals and append-only immutable Enterprise Position versions, a materialized current
-- position, the shared transactional outbox, and an optimistic version stamp. The
-- Governance context owns its own tables (Book III §3.5) — no sharing with Evidence /
-- Knowledge or the legacy tree.

CREATE TABLE IF NOT EXISTS findings (
    id                       TEXT PRIMARY KEY,       -- own opaque identity (never the CVE / Faultline id)
    release_id               TEXT NOT NULL,
    faultline_id             TEXT NOT NULL,          -- immutable reference to the global Faultline
    cve                      TEXT NOT NULL DEFAULT '', -- carried alias for thin events / reads
    stage                    TEXT NOT NULL,          -- investigation lifecycle stage
    version                  INT  NOT NULL,          -- optimistic-concurrency stamp
    current_stance           TEXT,                   -- materialized current Position stance (NULL until decided)
    current_position_version INT,                    -- materialized current Position version (NULL until decided)
    created_at               TIMESTAMPTZ NOT NULL,
    updated_at               TIMESTAMPTZ NOT NULL,
    UNIQUE (release_id, faultline_id)                -- the (Release, Faultline) business key (D1)
);

CREATE INDEX IF NOT EXISTS idx_findings_faultline ON findings (faultline_id);
CREATE INDEX IF NOT EXISTS idx_findings_release ON findings (release_id);

-- Matched components are content on the Finding (D1), idempotent by PURL — a re-scan of the
-- same occurrence records no new row.
CREATE TABLE IF NOT EXISTS finding_components (
    finding_id TEXT NOT NULL REFERENCES findings (id),
    purl       TEXT NOT NULL,
    name       TEXT NOT NULL DEFAULT '',
    version    TEXT NOT NULL DEFAULT '',
    ecosystem  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (finding_id, purl)
);

-- Append-only Governance Proposals (D4). The immutable columns (proposer / stance /
-- rationale / raised_at) never change; only the decision resolves once (Proposed →
-- Accepted/Rejected), so a re-save updates just the decision columns.
CREATE TABLE IF NOT EXISTS finding_proposals (
    finding_id    TEXT NOT NULL REFERENCES findings (id),
    proposal_id   TEXT NOT NULL,
    seq           INT  NOT NULL,            -- stable append order within a Finding
    proposer_kind TEXT NOT NULL,
    proposer_id   TEXT NOT NULL,
    stance        TEXT NOT NULL,
    rationale     TEXT NOT NULL DEFAULT '',
    raised_at     TIMESTAMPTZ NOT NULL,
    status        TEXT NOT NULL,
    decided_kind  TEXT NOT NULL DEFAULT '',
    decided_id    TEXT NOT NULL DEFAULT '',
    decided_at    TIMESTAMPTZ,
    PRIMARY KEY (finding_id, proposal_id)
);

-- Append-only immutable Enterprise Position versions (D3). Never updated or deleted.
CREATE TABLE IF NOT EXISTS finding_positions (
    finding_id           TEXT NOT NULL REFERENCES findings (id),
    version              INT  NOT NULL,
    stance               TEXT NOT NULL,
    rationale            TEXT NOT NULL DEFAULT '',
    actor_kind           TEXT NOT NULL,
    actor_id             TEXT NOT NULL,
    accepted_proposal_id TEXT NOT NULL DEFAULT '',
    faultline_ref        TEXT NOT NULL DEFAULT '',
    established_at        TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (finding_id, version)
);

-- Transactional outbox (BCK-0041): a Governance event is written in the same local
-- transaction as its aggregate mutation, then delivered by a background relay.
CREATE TABLE IF NOT EXISTS governance_outbox (
    id          TEXT PRIMARY KEY,
    finding_id  TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    payload     JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    sent_at     TIMESTAMPTZ,
    attempts    INT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_governance_outbox_unsent
    ON governance_outbox (occurred_at)
    WHERE sent_at IS NULL;
