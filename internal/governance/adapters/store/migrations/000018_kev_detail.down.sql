ALTER TABLE finding_positions DROP COLUMN IF EXISTS decided_kev_ransomware;
ALTER TABLE findings DROP COLUMN IF EXISTS signal_kev_ransomware;
ALTER TABLE findings DROP COLUMN IF EXISTS signal_kev_due;
