-- EDR-HARNESS-01: Themis commissions governed AI-runtime work against a Finding BEFORE it
-- runs (D-C-1). A commission is an immutable authority record; the only transition is
-- open -> withdrawn, forward-only, with its own witness (D-C-3). It never changes the
-- Finding's investigation stage (D-C-4).
CREATE TABLE IF NOT EXISTS finding_commissions (
    finding_id           TEXT NOT NULL REFERENCES findings (id),
    commission_id        TEXT NOT NULL,
    seq                  INT  NOT NULL,            -- stable append order within a Finding
    skill                TEXT NOT NULL,            -- runtime method name@version (opaque)
    composition_sha256   TEXT NOT NULL,            -- runtime composition hash (opaque)
    anchor               TEXT NOT NULL,            -- runtime deployment name@version (opaque)
    artifact_sha256      TEXT NOT NULL,            -- runtime anchor artifact hash (opaque)
    commissioned_kind    TEXT NOT NULL,
    commissioned_id      TEXT NOT NULL,
    premise_stage        TEXT NOT NULL,
    premise_position     INT  NOT NULL,
    rationale            TEXT NOT NULL DEFAULT '',
    raised_at            TIMESTAMPTZ NOT NULL,
    state                TEXT NOT NULL,            -- open | withdrawn
    withdrawn_kind       TEXT NOT NULL DEFAULT '',
    withdrawn_id         TEXT NOT NULL DEFAULT '',
    withdrawn_at         TIMESTAMPTZ,
    withdrawal_rationale TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (finding_id, commission_id)
);

-- A proposal whose evidence basis is a harness execution carries the immutable
-- harness-execution/v1 evidence (D-I-5) and the commission it ran under (D-C-5). Both are
-- written once with the proposal and never updated; the Position later cites the accepted
-- proposal by id, so the evidence travels by reference (D-I-6).
ALTER TABLE finding_proposals
  ADD COLUMN IF NOT EXISTS commission_id TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS harness_evidence JSONB;
