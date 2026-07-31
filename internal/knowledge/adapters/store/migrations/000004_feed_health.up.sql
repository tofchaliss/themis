-- Feed-health state (B1): one row per feed source recording its last successful sync, last
-- failure, and current failure streak. The scheduled workers upsert here on every poll; the
-- read side combines a row with its tier (domain.FeedObservation.Evaluate) into a tier-aware
-- health verdict surfaced at GET /feeds. This is the go-forward wiring of the D-FEED-2
-- taxonomy (domain/feedtier.go), which the v0.3.x feed_health never applied per tier.

CREATE TABLE IF NOT EXISTS feed_health (
    source               TEXT PRIMARY KEY,
    tier                 INT NOT NULL,
    last_success_at      TIMESTAMPTZ,
    last_failure_at      TIMESTAMPTZ,
    consecutive_failures INT NOT NULL DEFAULT 0,
    updated_at           TIMESTAMPTZ NOT NULL
);
