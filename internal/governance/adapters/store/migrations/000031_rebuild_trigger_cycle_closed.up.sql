-- EDR-REBUILD-01 step R3 (D21): a third trigger. When Communication closes a rebuild cycle that
-- other decisions had joined, the rebuild policy of the Release is evaluated once more. The
-- trigger id is the id of communication.rebuild_cycle_closed, and the source is "communication".
ALTER TABLE rebuild_triggers DROP CONSTRAINT IF EXISTS rebuild_triggers_trigger_type_check;
ALTER TABLE rebuild_triggers ADD CONSTRAINT rebuild_triggers_trigger_type_check
    CHECK (trigger_type IN ('new_sbom', 'fix_available', 'cycle_closed'));
