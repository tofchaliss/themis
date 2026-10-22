DROP TABLE IF EXISTS sla_breach_digest;
DROP TABLE IF EXISTS webhook_health;
DELETE FROM delivery_intents WHERE type = 'webhook';
ALTER TABLE delivery_intents DROP CONSTRAINT IF EXISTS delivery_intents_type_chk;
ALTER TABLE delivery_intents ADD CONSTRAINT delivery_intents_type_chk
    CHECK (type IN ('jira_issue', 'email', 'ci_rebuild'));
