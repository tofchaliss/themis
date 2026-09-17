DROP INDEX IF EXISTS idx_faultline_matches_active;
ALTER TABLE faultline_matches DROP COLUMN IF EXISTS retired_at;
