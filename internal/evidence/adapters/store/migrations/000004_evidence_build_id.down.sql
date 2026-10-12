-- Reverse 000004. Only the two columns go; no other column and no row is touched, so
-- every document and every receipt survives the reversal with the rest of its
-- provenance intact.
ALTER TABLE intake_receipts DROP COLUMN build_id;
ALTER TABLE evidence DROP COLUMN provenance_build_id;
