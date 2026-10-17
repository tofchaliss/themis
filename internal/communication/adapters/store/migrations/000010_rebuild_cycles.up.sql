-- EDR-DELIVERY-01 N-M2i / M2-5, M2-8: the rebuild LOOP's own state, one row per cycle.
--
-- A cycle opens when a new SBOM's evaluation leaves Critical or High Findings on a Release, and
-- captures the TARGETED SET then — it never grows (M2-5). Each later new_sbom evaluation of the
-- same Release is compared against that set; the loop continues (one more ci_rebuild intent),
-- SUCCEEDS (every targeted CVE closed) or is EXHAUSTED (the attempt limit reached). After a stop
-- no further intent is created for that cycle; a later new SBOM may open a NEW cycle.
--
-- `attempts` counts rebuilds ASKED FOR in this cycle — the loop's budget (M2-8), not the delivery
-- retry counter on the intent. The baseline for the next comparison is the SBOM evaluated last
-- (`last_sbom_id`): within a loop, the immediately-previous SBOM Themis judged IS the one the
-- rebuild was asked against.
CREATE TABLE IF NOT EXISTS rebuild_cycles (
    id               BIGSERIAL PRIMARY KEY,
    release_id       TEXT NOT NULL,
    origin_event_id  TEXT NOT NULL DEFAULT '',   -- the evaluation that opened the cycle
    baseline_sbom_id TEXT NOT NULL,              -- the SBOM whose evaluation opened the cycle
    last_sbom_id     TEXT NOT NULL,              -- the SBOM evaluated most recently in the cycle
    targeted_cves    TEXT[] NOT NULL,            -- captured once, sorted; never grows
    attempts         INTEGER NOT NULL DEFAULT 0, -- rebuilds asked for
    state            TEXT NOT NULL DEFAULT 'open',
    opened_at        TIMESTAMPTZ NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL,
    CONSTRAINT rebuild_cycles_state_chk CHECK (state IN ('open', 'succeeded', 'exhausted'))
);

-- At most ONE open cycle per Release: the loop's "is there a cycle to advance" question has one
-- answer, and two concurrent evaluations cannot open two.
CREATE UNIQUE INDEX IF NOT EXISTS uq_rebuild_cycles_open
    ON rebuild_cycles (release_id) WHERE state = 'open';
