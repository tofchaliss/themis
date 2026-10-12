-- Intake receipts (EDR-INTAKE-01 D9): the record of one intake attempt, including
-- the attempts that were REFUSED. A rejected receipt is the thing that was missing
-- on 2026-10-05, when a body was filed unreadable and nothing recorded that anyone
-- had tried; the operator's only feedback was a renderer on another screen, after
-- the immutable write.
--
-- Receipts are OPERATIONAL records, not evidence. They are deletable and are swept
-- after THEMIS_INTAKE_RECEIPT_TTL — which is why they live in their own table and
-- not beside the immutable `evidence` rows (CON-0007 has no delete).
--
-- The id columns are TEXT, not UUID, for the reason migration 000001 states about
-- `evidence.id`: this context's identities are opaque strings and the domain does
-- not mandate a format. `release_id` in particular MUST tolerate the empty string —
-- an attempt refused at detection (`unrecognised_format`) never reached release
-- resolution, and D9 requires that attempt to leave a receipt all the same. A
-- NOT NULL UUID column would have made the rejected receipt impossible for exactly
-- the refusals this table exists to record.
CREATE TABLE IF NOT EXISTS intake_receipts (
    intake_id        TEXT PRIMARY KEY,
    -- D12: the client's retry assertion. UNIQUE, and NULL for the submissions that
    -- assert no key — Postgres allows any number of NULLs in a unique index, which
    -- is exactly the semantics wanted: at most one receipt per asserted key, and no
    -- constraint at all on the keyless ones. Named explicitly because the write path
    -- dispatches on the violated constraint by name.
    idempotency_key  TEXT,
    status           TEXT NOT NULL CHECK (status IN
                        ('accepted', 'validating', 'converting', 'registering',
                         'filed', 'rejected', 'failed')),
    -- The reason and its elaboration are TWO columns and are never concatenated: a
    -- consumer switches on the reason and displays the detail. Governance flattened
    -- exactly this pair into "<reason>: <detail>", which turned a closed enum into
    -- free text and made every table lookup miss (fixed 2026-09-22). Empty, not
    -- NULL, when the attempt was not refused — "no reason" is a fact, not an unknown.
    reason           TEXT NOT NULL DEFAULT '',
    detail           TEXT NOT NULL DEFAULT '',
    -- Set only when the attempt reached `filed`.
    evidence_id      TEXT,
    release_id       TEXT NOT NULL DEFAULT '',
    detected_kind    TEXT NOT NULL DEFAULT '',
    detected_format  TEXT NOT NULL DEFAULT '',
    -- Both counts, never just the kept one: "427 of 427" and "427 of 500" must not
    -- look alike (KN-SCAN-OBS-1).
    findings_total   INTEGER NOT NULL DEFAULT 0,
    findings_skipped INTEGER NOT NULL DEFAULT 0,
    components       INTEGER NOT NULL DEFAULT 0,
    -- SHA-256 of the SUBMITTED bytes, which for a converted submission are not the
    -- filed bytes, plus the converter that produced those (D2: provenance is
    -- verifiable-by-digest, not reconstructable).
    source_digest    TEXT NOT NULL DEFAULT '',
    converted_by     TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT intake_receipts_idempotency_key_key UNIQUE (idempotency_key)
);

-- Serves both sweeps: the TTL retention purge and the startup recovery that fails
-- the non-terminal receipts a restart interrupted.
CREATE INDEX IF NOT EXISTS idx_intake_receipts_created_at ON intake_receipts (created_at);
