-- Reverse 000005. Only the one column goes; every receipt keeps the rest of its record.
ALTER TABLE intake_receipts DROP COLUMN components_skipped;
