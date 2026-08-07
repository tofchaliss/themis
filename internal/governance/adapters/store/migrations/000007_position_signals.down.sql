ALTER TABLE finding_positions DROP COLUMN IF EXISTS decided_epss;
ALTER TABLE finding_positions DROP COLUMN IF EXISTS decided_exploit_public;
ALTER TABLE finding_positions DROP COLUMN IF EXISTS decided_kev;
ALTER TABLE findings DROP COLUMN IF EXISTS signal_epss;
ALTER TABLE findings DROP COLUMN IF EXISTS signal_exploit_public;
ALTER TABLE findings DROP COLUMN IF EXISTS signal_kev;
