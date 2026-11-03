DROP INDEX IF EXISTS idx_finding_positions_scope_pending;
ALTER TABLE finding_positions DROP COLUMN IF EXISTS scope_applied_at;
ALTER TABLE finding_positions DROP COLUMN IF EXISTS propagated_from_version;
ALTER TABLE finding_positions DROP COLUMN IF EXISTS propagated_from_finding;
ALTER TABLE finding_positions DROP COLUMN IF EXISTS scope;
