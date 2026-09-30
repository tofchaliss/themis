-- Outward-action delivery intents (EDR-DELIVERY-01, N-M1a).
--
-- One row = one decision to act outside the estate (raise a Jira issue, send a mail, fire a
-- CI build) taken because a Governance fact crossed the bus. The event reader WRITES these
-- rows and does nothing else; separate per-channel workers read them and do the sending. So
-- an unreachable Jira cannot stall, fail or retry the governance stream — there is no sender
-- on the event path to be unreachable.
--
-- The row is a SNAPSHOT (D-N-3). snapshot holds the immutable lineage the intent was born
-- from, payload_bytes the deterministic materialization computed at record time, and
-- payload_hash the sha-256 of those bytes. A send that happens hours later therefore
-- delivers what the fact said THEN; regenerating from current state would quietly deliver a
-- different message than the one governance decided on. No credential is ever stored here:
-- `destination` is a governed NAME, and the worker's sender resolves it to an endpoint and a
-- secret it holds itself (D-N-6).
--
-- Statuses move FORWARD ONLY and nothing is deleted. PENDING -> DELIVERED / DEAD_LETTER /
-- CANCELLED; an operator Retry re-opens a terminal row to PENDING with attempts reset, which
-- adds a chapter to the history rather than erasing one.
--
-- WHY THE DEDUP KEY USES origin_event_id AND NOT THE BUS seq. The spec for this step names
-- (origin_event_seq, origin_event_type, kind, destination). The bus seq is deliberately NOT
-- part of the wire Envelope (internal/platform/eventbus/reader.go: "the seq is not part of
-- the wire Envelope") — it is the reader's cursor key, and a consuming context never sees it.
-- Putting it here would have meant widening the kernel Envelope, a cross-cutting change to
-- every context for a value that has an exact one-to-one stand-in already in hand: the
-- envelope id, which event_log stores beside seq and which the publisher is idempotent on.
-- So the guarantee asked for — one intent per (causing event, kind, destination), whatever
-- the bus replays or redelivers — is the one enforced, keyed on the identity that actually
-- crosses the boundary.

CREATE TABLE IF NOT EXISTS delivery_intents (
    id                TEXT PRIMARY KEY,
    kind              TEXT        NOT NULL,          -- jira_issue | email | ci_build
    destination       TEXT        NOT NULL,          -- governed target NAME, never a credential
    status            TEXT        NOT NULL,          -- PENDING | DELIVERED | DEAD_LETTER | CANCELLED
    attempts          INT         NOT NULL DEFAULT 0,
    max_attempts      INT         NOT NULL,
    last_error        TEXT        NOT NULL DEFAULT '',

    origin_event_id   TEXT        NOT NULL,          -- the causing bus envelope id (dedup identity)
    origin_event_type TEXT        NOT NULL,
    origin_event_time TIMESTAMPTZ NOT NULL,
    finding_id        TEXT        NOT NULL DEFAULT '',
    release_id        TEXT        NOT NULL DEFAULT '',
    product_id        TEXT        NOT NULL DEFAULT '',
    position_version  INT         NOT NULL DEFAULT 0,

    snapshot          JSONB       NOT NULL,
    payload_bytes     BYTEA       NOT NULL,
    payload_hash      CHAR(64)    NOT NULL,

    next_attempt_at   TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL,
    updated_at        TIMESTAMPTZ NOT NULL
);

-- The dedup guarantee: a replayed or redelivered event produces no second intent.
CREATE UNIQUE INDEX IF NOT EXISTS ux_delivery_intents_origin
    ON delivery_intents (origin_event_id, origin_event_type, kind, destination);

-- The workers' queue: PENDING rows of one kind that are due, oldest first.
CREATE INDEX IF NOT EXISTS idx_delivery_intents_due
    ON delivery_intents (kind, status, next_attempt_at);

-- The operator's list: "show me the failures".
CREATE INDEX IF NOT EXISTS idx_delivery_intents_status
    ON delivery_intents (status, created_at DESC);
