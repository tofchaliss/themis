-- Append-only send history for delivery intents (EDR-DELIVERY-01, N-M1a).
--
-- One row per send attempt: when, whether it worked, and what the other side said if it did
-- not. It is the audit of what Themis actually tried to do on the OUTSIDE world, which is
-- why it is append-only and why a retry never rewrites it — an operator asking "why did this
-- dead-letter" needs the failures, not just the count of them.
--
-- The cascade is deliberate and load-bearing in only one direction: intents are never
-- deleted in normal operation (statuses move forward), so it exists for the dev purge and
-- the down migration, not as a retention mechanism.

CREATE TABLE IF NOT EXISTS delivery_attempts (
    id           BIGSERIAL PRIMARY KEY,
    intent_id    TEXT        NOT NULL REFERENCES delivery_intents (id) ON DELETE CASCADE,
    attempt_no   INT         NOT NULL,
    ok           BOOLEAN     NOT NULL,
    error        TEXT        NOT NULL DEFAULT '',
    attempted_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_delivery_attempts_intent
    ON delivery_attempts (intent_id, attempt_no);
