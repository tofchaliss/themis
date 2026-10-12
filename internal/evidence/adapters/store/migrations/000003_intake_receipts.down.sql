-- Reverse 000003. The index belongs to the table and goes with it; receipts are
-- operational records, so dropping them loses no evidence (CON-0007 is untouched).
DROP TABLE IF EXISTS intake_receipts;
