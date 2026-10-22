DROP TABLE IF EXISTS review_warnings;
ALTER TABLE finding_positions DROP COLUMN IF EXISTS proof;
ALTER TABLE finding_positions DROP COLUMN IF EXISTS treatment;
ALTER TABLE finding_positions DROP COLUMN IF EXISTS owner;
