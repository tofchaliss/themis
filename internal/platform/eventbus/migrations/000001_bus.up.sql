-- Event Infrastructure (M5, EDR-EVENTBUS-01 D3/D4): the platform-owned `bus` database
-- holds the single event log — a Postgres stand-in for a Kafka topic. Each context's
-- relay copies its outbox rows here (the channel); stream Readers drain it in `seq`
-- order. Only the platform owns this table; producers and consumers never read each
-- other's databases (D3), so split-stability is structural, not disciplinary.

CREATE TABLE IF NOT EXISTS event_log (
    seq            BIGSERIAL PRIMARY KEY,   -- monotonic append order (one cursor → per-subject order, D6)
    envelope_id    TEXT NOT NULL UNIQUE,    -- kernel Envelope id; UNIQUE = at-most-once append + dedup key (D5)
    source_context TEXT NOT NULL,           -- the stream: routing + ordering unit (D7)
    subject        TEXT NOT NULL,           -- per-subject ordering key (D6)
    type           TEXT NOT NULL,           -- event type, e.g. "evidence.registered"
    occurred_at    TIMESTAMPTZ NOT NULL,    -- source state-transition time
    correlation_id TEXT NOT NULL,           -- ties events into a workflow across contexts
    schema_ref     TEXT NOT NULL,           -- integration-contract id of the payload (D9)
    payload        JSONB                    -- opaque producer-owned integration event
);

-- Stream drain: a Reader reads one stream (source_context) in seq order. The UNIQUE on
-- envelope_id already backs the dedup lookup, so no separate index is needed for it.
CREATE INDEX IF NOT EXISTS idx_event_log_stream ON event_log (source_context, seq);
