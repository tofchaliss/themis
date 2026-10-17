-- EDR-DELIVERY-01 N-M2d / M2-4: the release-evaluated EVENT STORE behind the cursor read API
-- GET /api/v1/governance/events/release-evaluated?after=<seq>&limit=<n>.
--
-- A cursor API cannot be served from a bus that has already delivered the message, so the
-- worker writes one row here in the SAME transaction that appends the outbox note and marks
-- the pending row published. The row is also the audit trail: what Themis said about a
-- Release, and when.
--
-- `seq` ORDERS (the cursor), `event_id` IDENTIFIES (the consumer's dedup key) — each does one
-- job (M2-4). No retention or purge policy on purpose: a purge that silently moves a cursor
-- past deleted rows is worse than growth an operator can measure.
CREATE TABLE IF NOT EXISTS release_evaluated_events (
    seq          BIGSERIAL PRIMARY KEY,
    event_id     TEXT NOT NULL UNIQUE,     -- the outbox envelope id, so the bus and the feed name one fact
    name         TEXT NOT NULL,            -- governance.release_evaluated
    release_id   TEXT NOT NULL,            -- carried verbatim for operators reading the table
    occurred_at  TIMESTAMPTZ NOT NULL,
    body         JSONB NOT NULL,           -- the governance.release_evaluated.v1 payload, as published
    recorded_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
