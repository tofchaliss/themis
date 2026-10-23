-- EDR-REMEDIATION-01 D7: free-form tags on a Product, a Project or a Release. Filters only —
-- nothing reads them to rank or decide. One row per (entity, tag); a Release's effective tags
-- are its own plus its Project's and Product's, computed on read.
CREATE TABLE IF NOT EXISTS registry_tags (
    entity_kind TEXT NOT NULL CHECK (entity_kind IN ('product', 'project', 'release')),
    entity_id   TEXT NOT NULL,
    tag         TEXT NOT NULL CHECK (char_length(tag) BETWEEN 1 AND 64),
    PRIMARY KEY (entity_kind, entity_id, tag)
);
CREATE INDEX IF NOT EXISTS idx_registry_tags_tag ON registry_tags (tag);
