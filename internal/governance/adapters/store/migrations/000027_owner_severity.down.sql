ALTER TABLE findings DROP COLUMN IF EXISTS owner_sla_bucket;
ALTER TABLE findings DROP COLUMN IF EXISTS owner_base_score;
DROP INDEX IF EXISTS idx_finding_owner_severities_finding;
DROP INDEX IF EXISTS idx_finding_owner_severities_current;
DROP TABLE IF EXISTS finding_owner_severities;
