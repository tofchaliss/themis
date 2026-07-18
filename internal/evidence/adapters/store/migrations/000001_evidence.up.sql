-- Evidence context schema. The Evidence context owns its own tables (Book III
-- §3.5; EDR-EVIDENCE-01 D2/D3/D7) — no sharing with other contexts or the legacy
-- tree, so this migration set is separate from the top-level migrations/.

CREATE TABLE IF NOT EXISTS evidence (
    -- Opaque, context-owned identity (EDR-EVIDENCE-01 D2): a string, not
    -- necessarily a UUID — the domain does not mandate a format.
    id                      TEXT PRIMARY KEY,
    kind                    TEXT NOT NULL CHECK (kind IN ('sbom', 'vex', 'scanner-report')),
    -- SHA-256 of the raw bytes: the content-addressed dedup identity (D3).
    fingerprint             TEXT NOT NULL UNIQUE,
    subject_release_id      TEXT NOT NULL,
    provenance_source       TEXT NOT NULL DEFAULT '',
    provenance_image_digest TEXT NOT NULL DEFAULT '',
    trust_status            TEXT NOT NULL CHECK (trust_status IN ('accepted', 'rejected')),
    -- The raw upload, frozen forever (immutable audit record, CON-0007).
    raw_document            BYTEA NOT NULL,
    -- The canonical component inventory translated at the door (D4).
    canonical_inventory     JSONB NOT NULL DEFAULT '{}',
    filed_at                TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_subject_release ON evidence (subject_release_id);

-- Transactional outbox (BCK-0041): the EvidenceRegistered note is written in the
-- same local transaction as its evidence row, then delivered by a background relay.
CREATE TABLE IF NOT EXISTS evidence_outbox (
    id          TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence (id),
    event_type  TEXT NOT NULL,
    payload     JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    sent_at     TIMESTAMPTZ,
    attempts    INT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_evidence_outbox_unsent
    ON evidence_outbox (occurred_at)
    WHERE sent_at IS NULL;
