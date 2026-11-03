-- EDR-INCIDENT-01 D2: the Watch — a named, operator-owned list of CVE and advisory identifiers
-- whose per-(release, CVE) state is COMPUTED ON READ from the Findings, the Positions and the
-- cards. This table holds the list only, never a state: a row here decides nothing and cannot
-- drift from the truth the table is read from.
--
-- identifiers is append-only in the aggregate (add, never silently drop); resolved_cves is the
-- CVE set the identifiers resolved to at the last status read, so a later reader can see what
-- an advisory meant THEN. notify is the D2a flag, recorded ahead of its emitter.
CREATE TABLE IF NOT EXISTS watches (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    created_by     TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL,
    identifiers    TEXT[] NOT NULL DEFAULT '{}',
    resolved_cves  TEXT[] NOT NULL DEFAULT '{}',
    resolved_at    TIMESTAMPTZ,
    notify         BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_watches_created ON watches (created_at DESC);
