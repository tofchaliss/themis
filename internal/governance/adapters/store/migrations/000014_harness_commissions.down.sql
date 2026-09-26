ALTER TABLE finding_proposals
  DROP COLUMN IF EXISTS harness_evidence,
  DROP COLUMN IF EXISTS commission_id;
DROP TABLE IF EXISTS finding_commissions;
