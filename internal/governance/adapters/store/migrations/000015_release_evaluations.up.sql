-- EDR-DELIVERY-01 N-M2b: the pending release-evaluation queue.
--
-- The inbound handler for knowledge.release_correlation_completed.v1 writes ONE row here,
-- inside the bus reader's inbox transaction, and does nothing else. It resolves no identity and
-- publishes nothing, because a handler error halts the whole Knowledge stream into Governance
-- after five attempts (EDR-EVENTBUS-01 D8) — so a Registry outage on the reader path would stop
-- Findings from opening. A background worker drains this queue: it resolves product + project,
-- counts the Release's Findings, and appends governance.release_evaluated.v1 to the outbox.
--
-- The queue is not an event store (that is N-M2d's `release_evaluated_events`): a row is a
-- to-do, and `published_at` is the only state it has.
CREATE TABLE IF NOT EXISTS release_evaluations_pending (
    id           BIGSERIAL PRIMARY KEY,
    release_id   TEXT NOT NULL,              -- Registry's release id, carried verbatim (never parsed)
    sbom_id      TEXT NOT NULL,              -- Evidence's id for the SBOM that was correlated
    cause        TEXT NOT NULL,              -- new_sbom | rediscovery, copied verbatim onto the event (M2-3)
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ,                -- NULL until the worker has published the event
    -- Idempotence on the triple, so a redelivered completion fact — or a second correlation of
    -- the same SBOM for the same reason — adds no second row. The envelope inbox already
    -- deduplicates one delivery; this deduplicates the FACT, which is the thing the worker acts
    -- on. A rediscovery of an SBOM already evaluated as new_sbom is a DIFFERENT fact and gets
    -- its own row, because the cause changes what a subscriber may do with it.
    UNIQUE (release_id, sbom_id, cause)
);

-- The worker's only read: the unpublished backlog, oldest first.
CREATE INDEX IF NOT EXISTS idx_release_evaluations_pending_unpublished
    ON release_evaluations_pending (received_at)
    WHERE published_at IS NULL;
