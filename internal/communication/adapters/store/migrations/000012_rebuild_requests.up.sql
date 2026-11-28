-- EDR-REBUILD-01 step R3: Communication acts on Governance's rebuild decision.
--
-- A cycle can now be opened by a DECISION (governance.rebuild_requested.v1) and no longer only
-- by the posture of an evaluation. Such a cycle keeps the frozen decision it was opened from
-- (every request of the cycle builds its payload from it, D36 and D40), counts refusals apart
-- from attempts (D20) and may stop as `refused`.
ALTER TABLE rebuild_cycles
    ADD COLUMN IF NOT EXISTS origin              TEXT NOT NULL DEFAULT 'evaluation', -- evaluation | decision
    ADD COLUMN IF NOT EXISTS decision_id         TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS decision            TEXT NOT NULL DEFAULT '',           -- the decision as it arrived
    ADD COLUMN IF NOT EXISTS product_id          TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS project_id          TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS refusals            INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS joined_decision_ids TEXT[] NOT NULL DEFAULT '{}',       -- decisions that joined (D13)
    ADD COLUMN IF NOT EXISTS closed_by           TEXT NOT NULL DEFAULT '',           -- the person who stopped it
    ADD COLUMN IF NOT EXISTS closed_note         TEXT NOT NULL DEFAULT '';

ALTER TABLE rebuild_cycles DROP CONSTRAINT IF EXISTS rebuild_cycles_state_chk;
ALTER TABLE rebuild_cycles ADD CONSTRAINT rebuild_cycles_state_chk
    CHECK (state IN ('open', 'succeeded', 'exhausted', 'refused', 'stopped'));
ALTER TABLE rebuild_cycles DROP CONSTRAINT IF EXISTS rebuild_cycles_origin_chk;
ALTER TABLE rebuild_cycles ADD CONSTRAINT rebuild_cycles_origin_chk
    CHECK (origin IN ('evaluation', 'decision'));

-- One row per request of a decision cycle: one intent, one attempt number, one try number (D23,
-- D40). The state uses the words of D25; `not_submitted` is a person's answer to `uncertain`
-- (D24). The row is evidence about a request. It changes no Finding.
CREATE TABLE IF NOT EXISTS rebuild_requests (
    intent_id            TEXT PRIMARY KEY,
    cycle_id             BIGINT NOT NULL REFERENCES rebuild_cycles (id),
    release_id           TEXT NOT NULL,
    decision_id          TEXT NOT NULL,
    attempt              INTEGER NOT NULL,
    try                  INTEGER NOT NULL,
    channel              TEXT NOT NULL,                 -- webhook | jenkins
    state                TEXT NOT NULL DEFAULT 'requested',
    reason               TEXT NOT NULL DEFAULT '',      -- what the connector or the sweep said
    build_ref            TEXT NOT NULL DEFAULT '',      -- the identity the build system gave (D38)
    execution_started_at TIMESTAMPTZ,
    requested_at         TIMESTAMPTZ NOT NULL,
    delivered_at         TIMESTAMPTZ,
    status_at            TIMESTAMPTZ,
    reported_by          TEXT NOT NULL DEFAULT '',
    settled_answer       TEXT NOT NULL DEFAULT '',
    settled_by           TEXT NOT NULL DEFAULT '',
    settled_at           TIMESTAMPTZ,
    settle_note          TEXT NOT NULL DEFAULT '',
    CONSTRAINT rebuild_requests_channel_chk CHECK (channel IN ('webhook', 'jenkins')),
    CONSTRAINT rebuild_requests_state_chk CHECK (state IN
        ('requested', 'delivered', 'submitted', 'refused', 'uncertain', 'not_submitted', 'build_reported', 'evaluated')),
    CONSTRAINT uq_rebuild_requests_try UNIQUE (cycle_id, attempt, try)
);
CREATE INDEX IF NOT EXISTS ix_rebuild_requests_release ON rebuild_requests (release_id, delivered_at);

-- A decision that opened no cycle, and why (D14 item 5): the cool-down, or a request route with
-- no signing secret (D6). One row per Release, replaced by the next one and removed when a cycle
-- opens.
CREATE TABLE IF NOT EXISTS rebuild_holds (
    release_id  TEXT PRIMARY KEY,
    decision_id TEXT NOT NULL,
    reason      TEXT NOT NULL,
    held_until  TIMESTAMPTZ,
    recorded_at TIMESTAMPTZ NOT NULL
);

-- The SBOM evaluated last per Release. A decision names no SBOM, so a cycle opened from one takes
-- its baseline here.
CREATE TABLE IF NOT EXISTS release_last_sbom (
    release_id   TEXT PRIMARY KEY,
    sbom_id      TEXT NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL
);
