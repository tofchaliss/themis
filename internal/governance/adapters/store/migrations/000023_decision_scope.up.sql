-- EDR-SYNC-01 D1/D3: the scope a decision was taken with, and where a propagated Position came
-- from. Both are inputs the decision rested on, immutable with the version like review_by.
--
-- scope: '' (release, the pre-record spelling) | 'project' | 'product'.
-- propagated_from_*: set only on a Position Governance applied from a scoped source; '' / 0 on
-- one a person established directly.
-- scope_applied_at: the queue. A directly taken scoped Position is pending until the sweep has
-- visited every target it reaches now; a propagated one is born applied (it is never a source).
-- The Position row IS the queue row, written in the accept's own transaction, so a scoped
-- decision can never be taken and lost.
ALTER TABLE finding_positions ADD COLUMN IF NOT EXISTS scope                   TEXT NOT NULL DEFAULT '';
ALTER TABLE finding_positions ADD COLUMN IF NOT EXISTS propagated_from_finding TEXT NOT NULL DEFAULT '';
ALTER TABLE finding_positions ADD COLUMN IF NOT EXISTS propagated_from_version INT  NOT NULL DEFAULT 0;
ALTER TABLE finding_positions ADD COLUMN IF NOT EXISTS scope_applied_at        TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_finding_positions_scope_pending
    ON finding_positions (established_at)
    WHERE scope IN ('project', 'product') AND scope_applied_at IS NULL;
