-- The severity BAND and the SELECTED fix versions, materialized onto each Finding (DASH-2 / PLAN-3).
--
-- Both are Knowledge's to compute and Governance's to serve. Rendering one release posture table
-- previously cost ~460 API calls — one Knowledge read per Faultline for the band, plus one
-- Governance assessment per Finding for the fix — because the rollup carried neither. A rollup
-- whose cost is linear in its own length cannot serve a dashboard.
--
-- Materialized rather than joined, for the same reason base_score is (C6/BUG-3): the values arrive
-- by EVENT from another bounded context, and a join would mean a cross-database read that the
-- database-per-context boundary exists to forbid.
--
-- `selected_fixes` is the per-component selection (AI-GROUND-1), not the card's cross-package
-- union: the union is what made a recommendation cite another package's version.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS band           TEXT  NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS selected_fixes JSONB NOT NULL DEFAULT '[]'::jsonb;
