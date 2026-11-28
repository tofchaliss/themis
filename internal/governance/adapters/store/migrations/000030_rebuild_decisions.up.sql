-- EDR-REBUILD-01 step R2 part 2 (D3, D9, D27, D29): rebuild triggers and rebuild decisions.
--
-- rebuild_triggers is the queue. A row is written in the same transaction as the event that
-- causes it (release_evaluated of a new SBOM, or fix_available), and trigger_id is that event's
-- id, so a trigger exists exactly when its event does and a repeated write adds nothing. The
-- worker closes a row with the outcome of the judgement: none (with the reason), recommend or
-- request.
--
-- rebuild_decisions is the audit copy of every judgement that ended in recommend or request:
-- the facts as they were read, frozen as JSON (D29). One decision per trigger. Nothing here
-- starts a build.
CREATE TABLE IF NOT EXISTS rebuild_triggers (
    id                BIGSERIAL PRIMARY KEY,
    trigger_id        TEXT        NOT NULL,
    trigger_source    TEXT        NOT NULL,
    trigger_type      TEXT        NOT NULL CHECK (trigger_type IN ('new_sbom', 'fix_available')),
    release_id        TEXT        NOT NULL,
    received_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    settled_at        TIMESTAMPTZ,
    outcome           TEXT        CHECK (outcome IN ('none', 'recommend', 'request')),
    reason            TEXT        NOT NULL DEFAULT '',
    effective_mode    TEXT        NOT NULL DEFAULT '',
    mode_set_by       TEXT        NOT NULL DEFAULT '',
    considered        INTEGER     NOT NULL DEFAULT 0,
    targeted          INTEGER     NOT NULL DEFAULT 0,
    decision_id       TEXT,
    CONSTRAINT rebuild_triggers_identity UNIQUE (trigger_source, trigger_id),
    CONSTRAINT rebuild_triggers_settled_check CHECK ((settled_at IS NULL) = (outcome IS NULL))
);

CREATE INDEX IF NOT EXISTS rebuild_triggers_pending_idx
    ON rebuild_triggers (received_at, id) WHERE settled_at IS NULL;
CREATE INDEX IF NOT EXISTS rebuild_triggers_release_idx
    ON rebuild_triggers (release_id, received_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS rebuild_decisions (
    decision_id    TEXT        PRIMARY KEY,
    release_id     TEXT        NOT NULL,
    trigger_source TEXT        NOT NULL,
    trigger_id     TEXT        NOT NULL,
    outcome        TEXT        NOT NULL CHECK (outcome IN ('recommend', 'request')),
    decided_at     TIMESTAMPTZ NOT NULL,
    facts          JSONB       NOT NULL,
    CONSTRAINT rebuild_decisions_trigger UNIQUE (trigger_source, trigger_id)
);

CREATE INDEX IF NOT EXISTS rebuild_decisions_release_idx
    ON rebuild_decisions (release_id, decided_at DESC);
