-- Triggers of the new kind and outcome cannot stay under the old checks. The decisions stay.
DELETE FROM rebuild_triggers WHERE trigger_type = 'mode_changed' OR outcome = 'unchanged';
ALTER TABLE rebuild_triggers DROP CONSTRAINT IF EXISTS rebuild_triggers_trigger_type_check;
ALTER TABLE rebuild_triggers ADD CONSTRAINT rebuild_triggers_trigger_type_check
    CHECK (trigger_type IN ('new_sbom', 'fix_available', 'cycle_closed'));
ALTER TABLE rebuild_triggers DROP CONSTRAINT IF EXISTS rebuild_triggers_outcome_check;
ALTER TABLE rebuild_triggers ADD CONSTRAINT rebuild_triggers_outcome_check
    CHECK (outcome IN ('none', 'recommend', 'request'));
DROP INDEX IF EXISTS rebuild_decisions_one_standing;
ALTER TABLE rebuild_decisions
    DROP COLUMN IF EXISTS retrigger,
    DROP COLUMN IF EXISTS cycle_closed_at,
    DROP COLUMN IF EXISTS approval,
    DROP COLUMN IF EXISTS superseded_by,
    DROP COLUMN IF EXISTS state_at,
    DROP COLUMN IF EXISTS state;
