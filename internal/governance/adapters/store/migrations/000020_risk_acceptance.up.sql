-- EDR-REMEDIATION-01 D2: risk-acceptance terms on a Position, and the review-warning log.
--
-- owner / treatment / proof are inputs the decision rested on, immutable with the version like
-- review_by: changing them is a new Position version. Empty on every stance other than
-- accepted_risk and deferred.
ALTER TABLE finding_positions ADD COLUMN IF NOT EXISTS owner     TEXT NOT NULL DEFAULT '';
ALTER TABLE finding_positions ADD COLUMN IF NOT EXISTS treatment TEXT NOT NULL DEFAULT '';
ALTER TABLE finding_positions ADD COLUMN IF NOT EXISTS proof     TEXT NOT NULL DEFAULT '';

-- One row per (Finding, Position version) warned that its review-by date is near, written with
-- the governance.review_due_soon.v1 outbox note in one transaction, so each version is warned
-- once. A new Position version is its own row.
CREATE TABLE IF NOT EXISTS review_warnings (
    finding_id       TEXT NOT NULL REFERENCES findings (id),
    position_version INT  NOT NULL,
    review_by        TIMESTAMPTZ NOT NULL,
    recorded_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (finding_id, position_version)
);
