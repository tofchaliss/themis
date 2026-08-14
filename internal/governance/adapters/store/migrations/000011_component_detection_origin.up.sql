-- KN-SCAN-2: which engine produced this match — `discovery` (feed correlation) or
-- `scanner/<name>` (an uploaded scanner report). Display provenance ONLY: it never enters a
-- decision, a policy, or the AI's grounding; authority stays with the trust class and the
-- source tier. It exists so an operator looking at a posture can answer "did a scanner or a
-- feed find this?" — before it, both roads converged on one Finding and the answer was
-- unrecoverable past the Knowledge card.
--
-- DEFAULT '' is `unknown` (a match recorded before the field existed), which the UI shows as
-- nothing rather than guessing — no backfill, existing rows keep exactly their present display.
ALTER TABLE finding_components ADD COLUMN IF NOT EXISTS detection_origin TEXT NOT NULL DEFAULT '';
