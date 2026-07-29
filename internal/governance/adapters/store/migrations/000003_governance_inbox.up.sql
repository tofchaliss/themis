-- Event Infrastructure (M5, EDR-EVENTBUS-01 D5) — the consumer inbox. processed_events
-- records every bus envelope this context has applied, keyed by the kernel envelope id.
-- The inbound apply inserts the id and does its business writes in ONE transaction, so a
-- redelivered envelope (the transport is at-least-once) is a no-op: exactly-once
-- application, not exactly-once delivery. Losing/rescanning the bus cursor is safe because
-- this table — not the cursor — is the correctness boundary.

CREATE TABLE IF NOT EXISTS processed_events (
    envelope_id  TEXT PRIMARY KEY,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
