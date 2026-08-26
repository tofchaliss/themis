-- Δ4a — the LLMOps replay harness store (EDR-INTELLIGENCE-01 § Δ4a, D-Δ4a-1). Four tables that
-- co-locate in the existing intelligence DB. Two of them (golden_entries, eval_reports) are the
-- node's FIRST NON-DISPOSABLE state: unlike position_embeddings (rebuildable) and invocation_log
-- (capped, disposable), they hold a curated regression suite and its scoring history that a
-- TRUNCATE would lose. This DB now needs a backup story (see INSTALLATION.md).
--
-- All state here is the node's OPERATIONAL state — attribution + a replay harness — never
-- enterprise truth. The eval tunes routing/versioning, never truth (INT-0065).

-- prompt_versions: a content-hash → version label per capability (D-Δ4a-3). Prompts stay
-- go:embed and reviewed; this is ATTRIBUTION, not serving. A boot upsert records the hash of
-- each capability's current template so every invocation and eval row can be attributed to it.
CREATE TABLE IF NOT EXISTS prompt_versions (
    capability   TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (capability, content_hash)
);

-- invocation_log: every reactive invocation, captured AFTER redaction (D-Δ4a-5). Disposable and
-- retention-capped (THEMIS_INTELLIGENCE_LOG_RETENTION). The raw material a human promotes golden
-- entries from — never a durable record in its own right.
CREATE TABLE IF NOT EXISTS invocation_log (
    correlation_id TEXT PRIMARY KEY,
    capability     TEXT NOT NULL,
    prompt_version TEXT NOT NULL DEFAULT '',
    model          TEXT NOT NULL DEFAULT '',
    tier           TEXT NOT NULL DEFAULT '',
    context_json   TEXT NOT NULL,    -- the assembled context, REDACTED on write (TEXT: the redactor rewrites substrings, so the stored form is a scrubbed STRING, not queryable JSON — see 000005)
    output_json    TEXT,             -- the model's raw output (redacted); null on a non-LLM decision
    reason         TEXT NOT NULL DEFAULT '',
    decline_class  TEXT NOT NULL DEFAULT '',
    tokens         INTEGER NOT NULL DEFAULT 0,
    occurred_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS invocation_log_occurred_at_idx ON invocation_log (occurred_at);

-- golden_entries: human-PROMOTED, durable, backed-up. A frozen (context, expected-outcome) pair
-- with a case label — the curated regression suite (D-Δ4a-2/5). expected_json holds the frozen
-- deterministic expectation (grounded refs, schema-validity, decline honesty) captured at
-- promotion time; source_correlation_id ties it back to the log entry it came from.
CREATE TABLE IF NOT EXISTS golden_entries (
    id                    TEXT PRIMARY KEY,
    label                 TEXT NOT NULL,
    capability            TEXT NOT NULL,
    source_correlation_id TEXT NOT NULL DEFAULT '',
    context_json          TEXT NOT NULL,    -- frozen assembled context (redacted; TEXT, see 000005)
    expected_json         JSONB NOT NULL,   -- frozen expected outcome
    promoted_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS golden_entries_capability_idx ON golden_entries (capability);

-- eval_reports: one row per eval run (D-Δ4a-6), durable and backed-up. results_json holds the
-- per-entry outcomes and the (capability, prompt_version, model) aggregate pass-rates. Live-model
-- only; run-it-yourself.
CREATE TABLE IF NOT EXISTS eval_reports (
    id           TEXT PRIMARY KEY,
    run_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    fingerprint  TEXT NOT NULL DEFAULT '', -- build/version fingerprint of the run
    entries      INTEGER NOT NULL DEFAULT 0,
    passed       INTEGER NOT NULL DEFAULT 0,
    results_json JSONB NOT NULL
);
