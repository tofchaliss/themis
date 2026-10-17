-- EDR-DELIVERY-01 N-M2f: ONE originating event may now ask for one intent PER TYPE.
--
-- A Release evaluation after a new SBOM asks for two outward actions at once — the ticket
-- update and the mail to the governed audience (M2-8 step 4) — and both are caused by the same
-- governance.release_evaluated.v1 envelope. Under the 000006 rule (one event → one intent) the
-- second would silently return the first. The dedup key becomes (event, type): a redelivery of
-- the envelope still adds nothing, and the two channels no longer compete for one row.
DROP INDEX IF EXISTS uq_delivery_intents_origin_event;
CREATE UNIQUE INDEX IF NOT EXISTS uq_delivery_intents_origin_event_type
    ON delivery_intents (origin_event_id, type) WHERE origin_event_id IS NOT NULL;
