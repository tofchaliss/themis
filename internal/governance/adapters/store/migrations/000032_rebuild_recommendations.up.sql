-- EDR-REBUILD-01 step R4 (D15, D26, D41, D44 to D46): the states of a rebuild recommendation.
--
-- A recommendation is a rebuild decision with outcome 'recommend'. It gets a state, and a
-- Release has at most one in state 'standing' (the unique index below keeps that). An approval
-- is stored on the decision it approves. A decision with outcome 'request' has no state ('').
ALTER TABLE rebuild_decisions
    ADD COLUMN IF NOT EXISTS state           TEXT        NOT NULL DEFAULT ''
        CHECK (state IN ('', 'standing', 'approved', 'superseded', 'expired', 'withdrawn')),
    ADD COLUMN IF NOT EXISTS state_at        TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS superseded_by   TEXT        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS approval        JSONB,
    ADD COLUMN IF NOT EXISTS cycle_closed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS retrigger       BOOLEAN     NOT NULL DEFAULT false;

-- Recommendations recorded before this step: the newest of each Release is the standing one
-- (its 7 days count from its own time), every older one was superseded by it.
UPDATE rebuild_decisions d
SET state = CASE WHEN r.rn = 1 THEN 'standing' ELSE 'superseded' END,
    state_at = d.decided_at,
    superseded_by = CASE WHEN r.rn = 1 THEN '' ELSE r.newest END
FROM (
    SELECT decision_id,
           row_number() OVER (PARTITION BY release_id ORDER BY decided_at DESC, decision_id DESC) AS rn,
           first_value(decision_id) OVER (PARTITION BY release_id ORDER BY decided_at DESC, decision_id DESC) AS newest
    FROM rebuild_decisions WHERE outcome = 'recommend'
) r
WHERE d.decision_id = r.decision_id AND d.state = '';

CREATE UNIQUE INDEX IF NOT EXISTS rebuild_decisions_one_standing
    ON rebuild_decisions (release_id) WHERE state = 'standing';

-- A trigger can now end in 'unchanged' (the same ask as the standing recommendation), and a
-- fourth trigger type exists: an approval that found the mode changed (D45 item 2).
ALTER TABLE rebuild_triggers DROP CONSTRAINT IF EXISTS rebuild_triggers_outcome_check;
ALTER TABLE rebuild_triggers ADD CONSTRAINT rebuild_triggers_outcome_check
    CHECK (outcome IN ('none', 'recommend', 'request', 'unchanged'));
ALTER TABLE rebuild_triggers DROP CONSTRAINT IF EXISTS rebuild_triggers_trigger_type_check;
ALTER TABLE rebuild_triggers ADD CONSTRAINT rebuild_triggers_trigger_type_check
    CHECK (trigger_type IN ('new_sbom', 'fix_available', 'cycle_closed', 'mode_changed'));
