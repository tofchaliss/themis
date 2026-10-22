-- EDR-REMEDIATION-01 D5: KEV detail on the exploitability picture.
--
-- The Finding's current signals gain CISA's due date and its ransomware-use flag; a Position's
-- decided-with premise gains the ransomware flag, so "ransomware use became known" can be
-- detected as drift exactly like KEV listing and EPSS rise (one-directional). The due date is
-- kept on the Finding for the SLA (D1: the earlier deadline wins); a Position does not need it.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS signal_kev_due        DATE;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS signal_kev_ransomware BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE finding_positions ADD COLUMN IF NOT EXISTS decided_kev_ransomware BOOLEAN NOT NULL DEFAULT FALSE;
