-- EDR-SCORING-01 S3: CVSS security requirements CR / IR / AR on a Product, a Project or a
-- Release. Append-only: every change is a new row with a reason and an actor, never an update;
-- the current value of a level is its latest row. X means "this level states nothing".
CREATE TABLE IF NOT EXISTS registry_security_requirements (
    seq         BIGSERIAL PRIMARY KEY,
    entity_kind TEXT NOT NULL CHECK (entity_kind IN ('product', 'project', 'release')),
    entity_id   TEXT NOT NULL,
    cr          TEXT NOT NULL CHECK (cr IN ('H', 'M', 'L', 'X')),
    ir          TEXT NOT NULL CHECK (ir IN ('H', 'M', 'L', 'X')),
    ar          TEXT NOT NULL CHECK (ar IN ('H', 'M', 'L', 'X')),
    reason      TEXT NOT NULL CHECK (char_length(reason) > 0),
    actor       TEXT NOT NULL CHECK (char_length(actor) > 0),
    via         TEXT NOT NULL DEFAULT '',
    recorded_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_registry_security_requirements_entity
    ON registry_security_requirements (entity_kind, entity_id, seq DESC);
