-- Intelligence context — the Operational Semantic Index (KS2, Book IV Chapter 8 /
-- EDR-INTELLIGENCE-01 Revision 4). This is the AI Gateway's ONLY datastore and it holds NO
-- truth: every row is a derived, rebuildable embedding of a past Enterprise Position that
-- Governance still owns (D12). Vectors are plain float32[] serialized little-endian into a
-- BYTEA column — NO pgvector extension — because the corpus (the enterprise's own <=~50k
-- Positions) is searched by brute-force cosine in-process, so Postgres only stores and
-- streams the vectors. Losing this table loses no knowledge; a rebuild re-reads the read-APIs.

CREATE TABLE IF NOT EXISTS position_embeddings (
    finding_id   TEXT PRIMARY KEY,          -- subject Finding identity (one current-position embedding per Finding)
    faultline_id TEXT NOT NULL DEFAULT '',  -- the global Faultline the decision concerns
    release_id   TEXT NOT NULL DEFAULT '',  -- the decision's Release (retrieval excludes the subject's own release)
    cve          TEXT NOT NULL DEFAULT '',  -- source CVE (precedent label)
    component    TEXT NOT NULL DEFAULT '',  -- representative component purl (precedent label)
    stance       TEXT NOT NULL DEFAULT '',  -- Enterprise Position stance (precedent label)
    rationale    TEXT NOT NULL DEFAULT '',  -- Position rationale (precedent label)
    model        TEXT NOT NULL,             -- embedding model id — a model swap is detectable and rebuildable
    dim          INT  NOT NULL,             -- vector dimensionality (guards decode)
    vector       BYTEA NOT NULL,            -- little-endian float32[] (dim*4 bytes); plain column, NO pgvector
    text_hash    TEXT NOT NULL DEFAULT '',  -- hash of the embedded text — population skips re-embed when unchanged
    updated_at   TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_position_embeddings_faultline ON position_embeddings (faultline_id);
CREATE INDEX IF NOT EXISTS idx_position_embeddings_model ON position_embeddings (model);
