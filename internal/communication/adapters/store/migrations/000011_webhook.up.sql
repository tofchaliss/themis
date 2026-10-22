-- EDR-REMEDIATION-01 D4: the one-way webhook channel.
--
-- The intent-type vocabulary admits `webhook`: an HTTPS POST of a small Themis JSON document to
-- the URL configured for a governed audience name.
ALTER TABLE delivery_intents DROP CONSTRAINT IF EXISTS delivery_intents_type_chk;
ALTER TABLE delivery_intents ADD CONSTRAINT delivery_intents_type_chk
    CHECK (type IN ('jira_issue', 'email', 'ci_rebuild', 'webhook'));

-- Health per webhook destination (audience name), DefectDojo's four states. Shown beside feed
-- health; it decides only whether the next send may be attempted.
CREATE TABLE IF NOT EXISTS webhook_health (
    destination          TEXT PRIMARY KEY,
    state                TEXT NOT NULL CHECK (state IN ('active', 'active_tmp', 'inactive_tmp', 'inactive_permanent')),
    consecutive_failures INT  NOT NULL DEFAULT 0,
    pauses               INT  NOT NULL DEFAULT 0,
    paused_until         TIMESTAMPTZ,
    last_success_at      TIMESTAMPTZ,
    last_failure_at      TIMESTAMPTZ,
    last_error           TEXT NOT NULL DEFAULT '',
    updated_at           TIMESTAMPTZ NOT NULL
);

-- SLA breaches waiting for the daily per-Product digest (D4: one message per Product per day,
-- never one per Finding). Written only when the sla_breached webhook route is configured; a row
-- is stamped with its digest when it is sent.
CREATE TABLE IF NOT EXISTS sla_breach_digest (
    finding_id   TEXT NOT NULL,
    period_start TIMESTAMPTZ NOT NULL,
    release_id   TEXT NOT NULL,
    cve          TEXT NOT NULL DEFAULT '',
    bucket       TEXT NOT NULL DEFAULT '',
    due          TIMESTAMPTZ NOT NULL,
    recorded_at  TIMESTAMPTZ NOT NULL,
    digest_id    TEXT,
    PRIMARY KEY (finding_id, period_start)
);
CREATE INDEX IF NOT EXISTS idx_sla_breach_digest_pending ON sla_breach_digest (recorded_at) WHERE digest_id IS NULL;
