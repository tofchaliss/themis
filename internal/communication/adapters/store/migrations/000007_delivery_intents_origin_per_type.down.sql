-- Reverting narrows the rule back to one intent per event. Rows that already hold two types for
-- one event would violate it, so they are kept and the index is recreated only when possible;
-- a failed CREATE here is the honest signal that the data no longer fits the old rule.
DROP INDEX IF EXISTS uq_delivery_intents_origin_event_type;
CREATE UNIQUE INDEX IF NOT EXISTS uq_delivery_intents_origin_event
    ON delivery_intents (origin_event_id) WHERE origin_event_id IS NOT NULL;
