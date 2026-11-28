DROP TABLE IF EXISTS release_last_sbom;
DROP TABLE IF EXISTS rebuild_holds;
DROP TABLE IF EXISTS rebuild_requests;
-- Cycles in the two new states are closed cycles; the old check knows them as exhausted.
UPDATE rebuild_cycles SET state = 'exhausted' WHERE state IN ('refused', 'stopped');
ALTER TABLE rebuild_cycles DROP CONSTRAINT IF EXISTS rebuild_cycles_origin_chk;
ALTER TABLE rebuild_cycles DROP CONSTRAINT IF EXISTS rebuild_cycles_state_chk;
ALTER TABLE rebuild_cycles ADD CONSTRAINT rebuild_cycles_state_chk
    CHECK (state IN ('open', 'succeeded', 'exhausted'));
ALTER TABLE rebuild_cycles
    DROP COLUMN IF EXISTS closed_note,
    DROP COLUMN IF EXISTS closed_by,
    DROP COLUMN IF EXISTS joined_decision_ids,
    DROP COLUMN IF EXISTS refusals,
    DROP COLUMN IF EXISTS project_id,
    DROP COLUMN IF EXISTS product_id,
    DROP COLUMN IF EXISTS decision,
    DROP COLUMN IF EXISTS decision_id,
    DROP COLUMN IF EXISTS origin;
