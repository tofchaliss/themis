ALTER TABLE sbom_documents
    ADD COLUMN deleted_at TIMESTAMPTZ DEFAULT NULL;

CREATE INDEX idx_sbom_documents_active ON sbom_documents (id) WHERE deleted_at IS NULL;
