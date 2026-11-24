-- EDR-PSIRT-01 revision 3: the PSIRT bulletin register. What an admin wrote about an issue,
-- never the world feed (EDR-KNOWLEDGE-01 D5 holds). A removal is a tombstone (removed_at), so a
-- bulletin is never deleted, and every write appends one history row in the same transaction.
CREATE TABLE IF NOT EXISTS psirt_bulletins (
    id           TEXT PRIMARY KEY,
    bulletin_id  TEXT NOT NULL,
    title        TEXT NOT NULL,
    bulletin_url TEXT NOT NULL DEFAULT '',
    alert_url    TEXT NOT NULL DEFAULT '',
    note         TEXT NOT NULL DEFAULT '',
    cve          TEXT NOT NULL DEFAULT '',
    report_date  DATE NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL,
    created_by   TEXT NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL,
    updated_by   TEXT NOT NULL,
    removed_at   TIMESTAMPTZ
);

-- One LIVE bulletin per bulletin ID and per CVE; a removed one frees both.
CREATE UNIQUE INDEX IF NOT EXISTS psirt_bulletins_live_id_idx ON psirt_bulletins (bulletin_id) WHERE removed_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS psirt_bulletins_live_cve_idx ON psirt_bulletins (cve) WHERE removed_at IS NULL AND cve <> '';

-- Every change: who, when, what, and the bulletin before and after (JSON; NULL before a create
-- and after a removal). Append-only.
CREATE TABLE IF NOT EXISTS psirt_bulletin_history (
    seq         BIGSERIAL PRIMARY KEY,
    bulletin    TEXT NOT NULL REFERENCES psirt_bulletins (id),
    at          TIMESTAMPTZ NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    before_json JSONB,
    after_json  JSONB
);
CREATE INDEX IF NOT EXISTS psirt_bulletin_history_bulletin_idx ON psirt_bulletin_history (bulletin, seq);
