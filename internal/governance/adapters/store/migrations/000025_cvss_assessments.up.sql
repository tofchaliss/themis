-- EDR-SCORING-01 S4 (shadow): per-component CVSS assessment revisions and Finding roll-up
-- revisions. Both are append-only: a revision is never updated, the current one is the newest,
-- and an old one is explained from its own snapshot (EDR 8.1, R-X5). The snapshot holds the
-- complete candidate evaluation as JSONB. Nothing reads these for priority yet.
CREATE TABLE IF NOT EXISTS component_score_revisions (
    seq          BIGSERIAL PRIMARY KEY,
    finding_id   TEXT NOT NULL,
    purl         TEXT NOT NULL,
    revision     INT  NOT NULL,
    cause        TEXT NOT NULL,
    fingerprint  TEXT NOT NULL,
    score_status TEXT NOT NULL,
    score        DOUBLE PRECISION,
    snapshot     JSONB NOT NULL,
    recorded_at  TIMESTAMPTZ NOT NULL,
    UNIQUE (finding_id, purl, revision)
);

CREATE TABLE IF NOT EXISTS finding_score_revisions (
    seq          BIGSERIAL PRIMARY KEY,
    finding_id   TEXT NOT NULL,
    revision     INT  NOT NULL,
    cause        TEXT NOT NULL,
    fingerprint  TEXT NOT NULL,
    state        TEXT NOT NULL,
    score        DOUBLE PRECISION,
    snapshot     JSONB NOT NULL,
    recorded_at  TIMESTAMPTZ NOT NULL,
    UNIQUE (finding_id, revision)
);
