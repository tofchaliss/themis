-- EDR-SCORING-01 S2: CVSS source truth beside the Proposals. Every table is append-only: rows
-- are inserted and never updated or deleted (R-S1). Current status, the latest grouping and the
-- latest validation are derived by reading, never stored as a mutable field.

-- One source revision as Themis received it (EDR 3.1). The fingerprint is the canonical content
-- hash; a revision equal to the document's LATEST one is a seen event, not a new row (R-S7). The
-- same fingerprint can recur: a document that changes back is a new revision.
CREATE TABLE IF NOT EXISTS rating_observations (
    id                     TEXT PRIMARY KEY,
    seq                    BIGSERIAL NOT NULL UNIQUE,
    cve                    TEXT NOT NULL,
    source                 TEXT NOT NULL,
    feed                   TEXT NOT NULL,
    document_ref           TEXT NOT NULL,
    revision               TEXT NOT NULL DEFAULT '',
    updated_original       TEXT NOT NULL DEFAULT '',
    updated_at             TIMESTAMPTZ,
    updated_interpretation TEXT NOT NULL DEFAULT '',
    fingerprint            TEXT NOT NULL,
    complete               BOOLEAN NOT NULL,
    applicability          TEXT[] NOT NULL DEFAULT '{}',
    severity_word          TEXT NOT NULL DEFAULT '',
    first_observed_at      TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS rating_observations_cve_idx ON rating_observations (cve);
CREATE INDEX IF NOT EXISTS rating_observations_doc_idx ON rating_observations (source, document_ref, seq DESC);

-- Every fetch of a document (EDR 3.1 SourceObservationSeenEvent).
CREATE TABLE IF NOT EXISTS rating_observation_seen (
    seq            BIGSERIAL PRIMARY KEY,
    observation_id TEXT NOT NULL REFERENCES rating_observations (id),
    source         TEXT NOT NULL,
    document_ref   TEXT NOT NULL,
    fetched_at     TIMESTAMPTZ NOT NULL,
    outcome        TEXT NOT NULL,
    endpoint       TEXT NOT NULL DEFAULT '',
    http_status    INTEGER NOT NULL DEFAULT 0,
    etag           TEXT NOT NULL DEFAULT '',
    last_modified  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS rating_observation_seen_obs_idx ON rating_observation_seen (observation_id);

-- One publication: a CVSS assessment as one observation carried it (EDR 3.1 SourceRating).
CREATE TABLE IF NOT EXISTS source_ratings (
    id                TEXT PRIMARY KEY,
    seq               BIGSERIAL NOT NULL UNIQUE,
    observation_id    TEXT NOT NULL REFERENCES rating_observations (id),
    cve               TEXT NOT NULL,
    source            TEXT NOT NULL,
    document_ref      TEXT NOT NULL,
    feed              TEXT NOT NULL,
    assessor          TEXT NOT NULL,
    publisher         TEXT NOT NULL DEFAULT '',
    nvd_type          TEXT NOT NULL DEFAULT '',
    cvss_version      TEXT NOT NULL,
    vector            TEXT NOT NULL,
    stated_score      NUMERIC(3,1),
    severity_word     TEXT NOT NULL DEFAULT '',
    asserted_context  TEXT NOT NULL DEFAULT '',
    inherited_context TEXT NOT NULL DEFAULT '',
    recorded_at       TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS source_ratings_cve_idx ON source_ratings (cve);
CREATE INDEX IF NOT EXISTS source_ratings_doc_idx ON source_ratings (source, document_ref);

-- The one terminal event of a publication (R-S12): the primary key makes a second impossible.
CREATE TABLE IF NOT EXISTS source_rating_events (
    rating_id                   TEXT PRIMARY KEY REFERENCES source_ratings (id),
    kind                        TEXT NOT NULL CHECK (kind IN ('superseded', 'withdrawn')),
    caused_by                   TEXT NOT NULL REFERENCES rating_observations (id),
    replaced_by                 TEXT REFERENCES source_ratings (id),
    source_time_original        TEXT NOT NULL DEFAULT '',
    source_time                 TIMESTAMPTZ,
    source_time_interpretation  TEXT NOT NULL DEFAULT '',
    learned_at                  TIMESTAMPTZ NOT NULL
);

-- What Themis computed about one publication with one calculator version (EDR 3.5).
CREATE TABLE IF NOT EXISTS rating_validations (
    rating_id          TEXT NOT NULL REFERENCES source_ratings (id),
    calculator_version TEXT NOT NULL,
    spec_version       TEXT NOT NULL DEFAULT '',
    result             TEXT NOT NULL,
    reason             TEXT NOT NULL DEFAULT '',
    base_score         NUMERIC(3,1),
    temporal_score     NUMERIC(3,1),
    stated_comparison  TEXT NOT NULL DEFAULT '',
    validated_at       TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (rating_id, calculator_version)
);

-- The complete grouping of one identity set, each time it changes (EDR 3.2a AssessmentLink).
CREATE TABLE IF NOT EXISTS assessment_links (
    seq            BIGSERIAL PRIMARY KEY,
    cve            TEXT NOT NULL,
    set_key        TEXT NOT NULL,
    grouping       JSONB NOT NULL,
    changes        JSONB NOT NULL DEFAULT '[]',
    policy_version TEXT NOT NULL,
    cause          TEXT NOT NULL,
    at             TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS assessment_links_cve_idx ON assessment_links (cve, set_key, seq);
