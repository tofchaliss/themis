-- EDR-REBUILD-01 D10, D16 (step R2a): the build profile of a Project, and the optional one of a
-- Release that replaces the Project's as a whole. Append-only: every change is a new row with
-- its actor and its own revision number, a removal is a row too (removed = true, no profile),
-- and the current value of a level is its latest row. The profile is stored as the exact
-- compact text that is served, sent and hashed, so it is TEXT and not JSONB: JSONB would
-- reorder keys and the digest of D16 would no longer match what a reader sees.
CREATE TABLE IF NOT EXISTS registry_build_profiles (
    seq         BIGSERIAL PRIMARY KEY,
    entity_kind TEXT        NOT NULL CHECK (entity_kind IN ('project', 'release')),
    entity_id   TEXT        NOT NULL,
    revision    INTEGER     NOT NULL CHECK (revision > 0),
    profile     TEXT,
    removed     BOOLEAN     NOT NULL DEFAULT false,
    actor       TEXT        NOT NULL CHECK (char_length(actor) > 0),
    via         TEXT        NOT NULL DEFAULT '',
    recorded_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT registry_build_profiles_revision UNIQUE (entity_kind, entity_id, revision),
    CONSTRAINT registry_build_profiles_removed_check CHECK (removed = (profile IS NULL)),
    CONSTRAINT registry_build_profiles_size_check CHECK (profile IS NULL OR octet_length(profile) <= 16384)
);
