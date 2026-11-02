-- EDR-INCIDENT-01 D1: the fix-published notices. Knowledge says, per occurrence, that a vendor
-- fix is newly on record for a package this release has OPEN (knowledge.fix_published.v1); the
-- inbound consumer records each here inside the inbox transaction, and the fix-available sweep
-- gathers the unannounced rows of one release into ONE governance.fix_available.v1, marking them
-- announced in the same transaction as the outbox note. A notice decides nothing.
--
-- Keyed by (release, faultline, purl, fix): a re-delivery or a restatement records nothing new.
-- The Finding is joined at read time, never stored — the notice may arrive before Governance
-- opened it, and the join is also where a not_affected release is kept out of the announcement.
CREATE TABLE IF NOT EXISTS fix_notices (
    release_id    TEXT NOT NULL,
    faultline_id  TEXT NOT NULL,
    purl          TEXT NOT NULL,
    fix           TEXT NOT NULL,
    cve           TEXT NOT NULL DEFAULT '',
    package       TEXT NOT NULL DEFAULT '',
    ecosystem     TEXT NOT NULL DEFAULT '',
    advisories    TEXT[] NOT NULL DEFAULT '{}',
    learned_at    TIMESTAMPTZ NOT NULL,
    announced_at  TIMESTAMPTZ,
    announcement  TEXT NOT NULL DEFAULT '',   -- the outbox note id the row went out in
    PRIMARY KEY (release_id, faultline_id, purl, fix)
);

CREATE INDEX IF NOT EXISTS idx_fix_notices_pending ON fix_notices (learned_at) WHERE announced_at IS NULL;
