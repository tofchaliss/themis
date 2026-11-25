-- EDR-SCORING-01 section 7.1 (OS1-OS2): the severity a named person set for one Finding.
--
-- finding_owner_severities is the record. A row is never deleted or rewritten: setting a new
-- severity, or removing it, ENDS the row in force (ended_at, ended_by, end_cause) and the
-- history stays. At most one row per Finding is in force (the partial unique index).
CREATE TABLE IF NOT EXISTS finding_owner_severities (
    id             BIGSERIAL PRIMARY KEY,
    finding_id     TEXT        NOT NULL,
    kind           TEXT        NOT NULL CHECK (kind IN ('level', 'vector')),
    level          TEXT        NOT NULL CHECK (level IN ('none', 'low', 'medium', 'high', 'critical')),
    vector         TEXT        NOT NULL DEFAULT '',
    score          DOUBLE PRECISION NOT NULL,
    original_score DOUBLE PRECISION,
    reason         TEXT        NOT NULL,
    actor_id       TEXT        NOT NULL,
    set_at         TIMESTAMPTZ NOT NULL,
    picked_from    TEXT        NOT NULL DEFAULT '',
    ended_at       TIMESTAMPTZ,
    ended_by       TEXT        NOT NULL DEFAULT '',
    end_cause      TEXT        NOT NULL DEFAULT '' CHECK (end_cause IN ('', 'replaced', 'removed'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_finding_owner_severities_current
    ON finding_owner_severities (finding_id) WHERE ended_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_finding_owner_severities_finding
    ON finding_owner_severities (finding_id, id);

-- The read columns. owner_base_score is the owner-set score on the 0-100 scale, NULL when no
-- owner-set severity is in force; owner_sla_bucket is its deadline bucket. Priority, the
-- deadline and the severity counts read these before base_score / sla_bucket, which keep the
-- original untouched so that removing the owner-set severity brings the original back.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS owner_base_score INT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS owner_sla_bucket TEXT NOT NULL DEFAULT '';
