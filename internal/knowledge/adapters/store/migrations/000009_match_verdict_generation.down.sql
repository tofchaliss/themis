DROP INDEX IF EXISTS idx_faultline_matches_verdict_stamps;
ALTER TABLE faultline_matches DROP COLUMN IF EXISTS verdict_generation;
