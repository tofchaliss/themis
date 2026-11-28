ALTER TABLE rebuild_policy_history DROP COLUMN IF EXISTS removed;
ALTER TABLE rebuild_policies
    DROP CONSTRAINT IF EXISTS rebuild_policies_scope_id_check,
    DROP CONSTRAINT IF EXISTS rebuild_policies_scope_kind_check;
