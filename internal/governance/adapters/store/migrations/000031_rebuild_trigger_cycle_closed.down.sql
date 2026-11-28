-- Triggers of the third kind cannot stay under the old check. They are closed queue rows or
-- open ones nobody would judge after the downgrade; their decisions stay in rebuild_decisions.
DELETE FROM rebuild_triggers WHERE trigger_type = 'cycle_closed';
ALTER TABLE rebuild_triggers DROP CONSTRAINT IF EXISTS rebuild_triggers_trigger_type_check;
ALTER TABLE rebuild_triggers ADD CONSTRAINT rebuild_triggers_trigger_type_check
    CHECK (trigger_type IN ('new_sbom', 'fix_available'));
