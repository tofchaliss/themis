DROP INDEX IF EXISTS idx_faultlines_reclassify;
ALTER TABLE faultlines DROP COLUMN IF EXISTS reclassified_generation;
ALTER TABLE faultlines DROP COLUMN IF EXISTS reclassified_version;
