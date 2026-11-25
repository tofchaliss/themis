-- EDR-SYNC-01 revision 2 (D9, D11): the Findings a decision is copied to, once.
--
-- copy_to: the Finding ids the decider picked; empty on a decision taken for its own Finding
-- only, and on every copy (a copy is never copied further).
-- copy_applied_at: the queue, like scope_applied_at. A Position that names targets is pending
-- until the sweep has made its copies. The Position row IS the queue row, written in the
-- accept's own transaction, so a decision can never be recorded and its copies lost.
ALTER TABLE finding_positions ADD COLUMN IF NOT EXISTS copy_to         TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE finding_positions ADD COLUMN IF NOT EXISTS copy_applied_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_finding_positions_copy_pending
    ON finding_positions (established_at)
    WHERE cardinality(copy_to) > 0 AND copy_applied_at IS NULL;
