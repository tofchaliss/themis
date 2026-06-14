DROP INDEX IF EXISTS idx_vex_documents_source;
DROP INDEX IF EXISTS idx_vex_assertions_component_purl;

ALTER TABLE vex_assertions DROP COLUMN IF EXISTS match_type;

ALTER TABLE vex_documents DROP CONSTRAINT IF EXISTS vex_documents_source_check;
ALTER TABLE vex_documents ADD CONSTRAINT vex_documents_source_check
    CHECK (source IN ('vendor', 'upstream', 'manual', 'themis_generated'));

-- Restore NOT NULL only when no orphan rows exist.
ALTER TABLE vex_documents ALTER COLUMN sbom_document_id SET NOT NULL;
