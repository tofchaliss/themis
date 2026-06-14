DROP INDEX IF EXISTS idx_sbom_documents_active;
ALTER TABLE sbom_documents DROP COLUMN IF EXISTS deleted_at;
