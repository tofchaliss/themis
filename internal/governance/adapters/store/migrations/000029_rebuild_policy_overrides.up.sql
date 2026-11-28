-- EDR-REBUILD-01 step R1a (D11): Product and Release rebuild policies beside the installation's.
--
-- The scope columns of migration 28 already hold them. This migration names the three scope
-- kinds, ties the scope id to the kind (the installation has none, a Product or a Release must
-- name one), and lets the history record the REMOVAL of an override: a removed policy leaves
-- rebuild_policies, and its last values stay in rebuild_policy_history with removed = true,
-- the actor and the time. The version of a scope keeps counting across a removal.
ALTER TABLE rebuild_policies
    ADD CONSTRAINT rebuild_policies_scope_kind_check
        CHECK (scope_kind IN ('installation', 'product', 'release')),
    ADD CONSTRAINT rebuild_policies_scope_id_check
        CHECK ((scope_kind = 'installation') = (scope_id = ''));

ALTER TABLE rebuild_policy_history
    ADD COLUMN IF NOT EXISTS removed BOOLEAN NOT NULL DEFAULT false;
