DROP TABLE IF EXISTS sla_breaches;
DROP TABLE IF EXISTS sla_policies;
ALTER TABLE findings DROP COLUMN IF EXISTS stage_stopped_at;
ALTER TABLE findings DROP COLUMN IF EXISTS sla_bucket;
