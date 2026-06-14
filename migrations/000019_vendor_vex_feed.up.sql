-- Upstream vendor VEX feed support (Phase 2a Group 25).

ALTER TABLE vex_documents ALTER COLUMN sbom_document_id DROP NOT NULL;

ALTER TABLE vex_documents DROP CONSTRAINT IF EXISTS vex_documents_source_check;
ALTER TABLE vex_documents ADD CONSTRAINT vex_documents_source_check
    CHECK (source IN ('vendor', 'upstream', 'upstream_vendor', 'manual', 'themis_generated'));

ALTER TABLE vex_assertions ADD COLUMN IF NOT EXISTS match_type TEXT
    CHECK (match_type IS NULL OR match_type IN (
        'exact', 'namespace_normalised', 'version_inherited', 'range_matched'
    ));

CREATE INDEX IF NOT EXISTS idx_vex_assertions_component_purl
    ON vex_assertions (component_purl)
    WHERE component_purl IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_vex_documents_source
    ON vex_documents (source);
