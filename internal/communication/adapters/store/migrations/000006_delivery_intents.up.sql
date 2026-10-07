-- Outward-delivery intents (N-M1a — EDR-DELIVERY-01 Revision 3).
--
-- An INTENT is the durable record "this must go out", written by the inbound event reader
-- inside the inbox unit of work and never by a caller waiting on Jira or a mail relay. The
-- reader's whole job is to persist the row; the sending happens later, in a worker, so an
-- unreachable external system can never block, slow or stall the bus reader path (RC-7:
-- external availability never changes Themis truth).
--
-- IDENTITY / IDEMPOTENCE: origin_event_id is the kernel envelope id of the event that caused
-- the intent, and the partial unique index below is the deduplication rule. The transport is
-- at-least-once, so the SAME event can arrive twice; one event maps to one intent per mapping,
-- and a replay therefore conflicts instead of enqueuing a second ticket or a second mail.
-- It is NULL for worker-originated intents (the dead-letter notification), which have no
-- originating event — NULLs are distinct in a unique index, so those never collide.
--
-- snapshot holds the immutable facts as they were at intent creation: the delivery payload is
-- derived from it and from nothing else, so no model output, no workspace content and no
-- credential can reach an outward system through this table. payload_sha256/payload_bytes are
-- the content-address + rendered-body columns the materialization step (N-M1b) fills; N-M1a
-- leaves them at their empty defaults rather than inventing a shape the real Jira/mail
-- senders have not yet fixed.
--
-- The foreign ids (product/project/release/finding/proposal) are TEXT, not UUID: they are
-- OTHER contexts' identities, carried verbatim and never parsed, so no format is imposed on
-- Registry or Governance (the same rule EDR-DELIVERY-01 D5 applies to `product:<id>`). The
-- intent's own id is a UUID because Communication mints it.
CREATE TABLE IF NOT EXISTS delivery_intents (
    id              UUID PRIMARY KEY,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    type            TEXT NOT NULL,
    destination     TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'pending',
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_attempt_at TIMESTAMPTZ,
    last_error      TEXT NOT NULL DEFAULT '',
    result          JSONB NOT NULL DEFAULT '{}',
    payload_sha256  TEXT NOT NULL DEFAULT '',
    payload_bytes   BYTEA NOT NULL DEFAULT '\x',
    snapshot        JSONB NOT NULL,
    lineage         JSONB NOT NULL,
    origin_event_id TEXT,
    product_id      TEXT NOT NULL DEFAULT '',
    project_id      TEXT NOT NULL DEFAULT '',
    release_id      TEXT NOT NULL DEFAULT '',
    finding_id      TEXT NOT NULL DEFAULT '',
    proposal_id     TEXT NOT NULL DEFAULT '',
    CONSTRAINT delivery_intents_type_chk  CHECK (type IN ('jira_issue', 'email')),
    CONSTRAINT delivery_intents_state_chk CHECK (state IN ('pending', 'delivered', 'dead_letter', 'cancelled'))
);

-- The deduplication rule itself (one originating event -> one intent).
CREATE UNIQUE INDEX IF NOT EXISTS uq_delivery_intents_origin_event
    ON delivery_intents (origin_event_id) WHERE origin_event_id IS NOT NULL;

-- The worker's claim order (next_attempt_at asc, attempts asc) over pending rows only.
CREATE INDEX IF NOT EXISTS idx_delivery_intents_work
    ON delivery_intents (next_attempt_at, attempts) WHERE state = 'pending';

-- The operator's view: dead-letters newest first.
CREATE INDEX IF NOT EXISTS idx_delivery_intents_state
    ON delivery_intents (state, updated_at DESC);

-- Every attempt, append-only: the audit of what was tried, when, and what came back. It is
-- separate from the intent's attempts counter because the counter answers "may we try again"
-- while these rows answer "what happened" — and the second question survives a retry reset.
CREATE TABLE IF NOT EXISTS delivery_attempts (
    id               BIGSERIAL PRIMARY KEY,
    intent_id        UUID NOT NULL REFERENCES delivery_intents (id) ON DELETE CASCADE,
    attempt_no       INT NOT NULL,
    attempted_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    outcome          TEXT NOT NULL,
    status_code      INT,
    response_excerpt TEXT NOT NULL DEFAULT '',
    error            TEXT NOT NULL DEFAULT '',
    CONSTRAINT delivery_attempts_outcome_chk CHECK (outcome IN ('success', 'failure'))
);

CREATE INDEX IF NOT EXISTS idx_delivery_attempts_intent
    ON delivery_attempts (intent_id, attempt_no);
