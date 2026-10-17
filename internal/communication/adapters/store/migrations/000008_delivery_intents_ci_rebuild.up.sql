-- EDR-DELIVERY-01 N-M2g: the intent-type vocabulary admits `ci_rebuild` (RC-3's fourth kind —
-- M2-6, the Jenkins buildWithParameters sender). `ci_build` is still NOT admitted: it keeps its
-- governance-controlled path and has no sender.
ALTER TABLE delivery_intents DROP CONSTRAINT IF EXISTS delivery_intents_type_chk;
ALTER TABLE delivery_intents ADD CONSTRAINT delivery_intents_type_chk
    CHECK (type IN ('jira_issue', 'email', 'ci_rebuild'));
