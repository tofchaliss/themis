-- EDR-REMEDIATION-01 D1: the SLA policy and the clock's bookkeeping (D8 Q1/Q2/Q5, S1/S2).
--
-- sla_bucket is the severity bucket FROZEN when the Finding first had a base score (Q1): a later
-- score change is shown beside it and never moves the deadline. Existing Findings are frozen at
-- their current score, the first one this table ever saw.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS sla_bucket TEXT NOT NULL DEFAULT '';
UPDATE findings SET sla_bucket = CASE
        WHEN base_score >= 90 THEN 'critical'
        WHEN base_score >= 70 THEN 'high'
        WHEN base_score >= 40 THEN 'medium'
        WHEN base_score > 0  THEN 'low'
        ELSE '' END
 WHERE sla_bucket = '';

-- stage_stopped_at is when the Finding reached resolved/archived, so a stage stop can be graded
-- met or missed. NULL for older stops: unknown, read as not_applicable, never guessed.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS stage_stopped_at TIMESTAMPTZ;

-- One row per scope: '' is the estate policy, otherwise a Product id. No row for the estate
-- means the shipped defaults (7/30/90/180, all enforced).
CREATE TABLE IF NOT EXISTS sla_policies (
    scope            TEXT PRIMARY KEY,
    critical_days    INT NOT NULL,
    critical_enforce BOOLEAN NOT NULL,
    high_days        INT NOT NULL,
    high_enforce     BOOLEAN NOT NULL,
    medium_days      INT NOT NULL,
    medium_enforce   BOOLEAN NOT NULL,
    low_days         INT NOT NULL,
    low_enforce      BOOLEAN NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL,
    updated_by       TEXT NOT NULL DEFAULT ''
);

-- The breach log: one row per (Finding, SLA period) whose due date passed, written with the
-- governance.sla_breached.v1 outbox note in one transaction. It is the ONLY write of the breach
-- path (S1); a period restarted after an acceptance gets its own row (S2).
CREATE TABLE IF NOT EXISTS sla_breaches (
    finding_id   TEXT NOT NULL REFERENCES findings (id),
    period_start TIMESTAMPTZ NOT NULL,
    due          TIMESTAMPTZ NOT NULL,
    recorded_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (finding_id, period_start)
);
