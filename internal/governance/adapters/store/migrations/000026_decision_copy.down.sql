DROP INDEX IF EXISTS idx_finding_positions_copy_pending;
ALTER TABLE finding_positions DROP COLUMN IF EXISTS copy_applied_at;
ALTER TABLE finding_positions DROP COLUMN IF EXISTS copy_to;
