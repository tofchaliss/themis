-- Reverting narrows the vocabulary again. Rows of type ci_rebuild would violate the old
-- constraint, so they are REMOVED first: a rebuild intent is an instruction to a build system,
-- not a record of truth, and an estate rolling this migration back has decided not to send them.
DELETE FROM delivery_intents WHERE type = 'ci_rebuild';
ALTER TABLE delivery_intents DROP CONSTRAINT IF EXISTS delivery_intents_type_chk;
ALTER TABLE delivery_intents ADD CONSTRAINT delivery_intents_type_chk
    CHECK (type IN ('jira_issue', 'email'));
