-- Event Infrastructure (M5, EDR-EVENTBUS-01 D5/D7) — the read side.
--
-- insert_xid8 records each row's inserting transaction id (xid8, wraparound-safe). A stream
-- Reader advances a gap-free watermark with it: it reads only rows whose inserting
-- transaction is already settled relative to pg_snapshot_xmin(pg_current_snapshot()), so it
-- never steps over a lower seq whose transaction has not yet become visible (the
-- concurrent-append / commit-visibility gap; D7's gap-free observable contract). The
-- Publisher (EB-04) writes a single row per transaction and lists explicit columns, so the
-- column DEFAULT populates this with no producer change; xid order then matches seq order.
--
-- stream_cursor is the per-consumer read position — a PostgreSQL-era read optimization only
-- (D5): correctness is the consumer's processed_events inbox, so losing the cursor and
-- rescanning from zero is a no-op, not a bug.

ALTER TABLE event_log
    ADD COLUMN insert_xid8 xid8 NOT NULL DEFAULT pg_current_xact_id();

CREATE TABLE IF NOT EXISTS stream_cursor (
    consumer       TEXT NOT NULL,             -- the subscribing consumer (e.g. "governance")
    source_context TEXT NOT NULL,             -- the subscribed stream (event_log.source_context)
    last_seq       BIGINT NOT NULL DEFAULT 0, -- highest seq whose Handle succeeded for this (consumer, stream)
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (consumer, source_context)
);
