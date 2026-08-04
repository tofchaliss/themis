-- Event Infrastructure (M5, EDR-EVENTBUS-01 D5) — the consumer inbox. Intelligence becomes a
-- bus consumer for the first time (EDR-INTELLIGENCE-01 Rev 4, R6): the population consumer
-- (A4) drains governance.position_established (and knowledge.faultline_enriched) to keep the
-- Operational Semantic Index fresh. processed_events records every applied envelope, keyed by
-- the kernel envelope id, so a redelivered envelope (the transport is at-least-once) is a
-- no-op: exactly-once application, not exactly-once delivery. The bus cursor is disposable;
-- this table — not the cursor — is the correctness boundary.

CREATE TABLE IF NOT EXISTS processed_events (
    envelope_id  TEXT PRIMARY KEY,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
