CREATE TABLE sbom_documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    image_id UUID NOT NULL REFERENCES images(id),
    project_id UUID REFERENCES projects(id),
    image_digest TEXT NOT NULL,
    checksum_sha256 TEXT NOT NULL,
    format TEXT NOT NULL CHECK (format IN ('cyclonedx', 'spdx', 'trivy')),
    spec_version TEXT,
    scanner_name TEXT,
    scanner_version TEXT,
    scanner_db_version TEXT,
    ci_job_id TEXT,
    ci_pipeline_url TEXT,
    build_timestamp TIMESTAMPTZ,
    trigger_source TEXT,
    supplier_identity TEXT,
    upstream_origin TEXT,
    signature TEXT,
    signature_format TEXT,
    signer_identity TEXT,
    signature_verified BOOLEAN NOT NULL DEFAULT FALSE,
    trust_status TEXT NOT NULL DEFAULT 'unsigned'
        CHECK (trust_status IN ('verified', 'unverified', 'failed', 'unsigned')),
    is_latest BOOLEAN NOT NULL DEFAULT TRUE,
    supersedes_id UUID REFERENCES sbom_documents(id),
    raw_document JSONB NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (image_digest, checksum_sha256)
);

CREATE INDEX idx_sbom_documents_image_id ON sbom_documents (image_id);
CREATE INDEX idx_sbom_documents_project_id ON sbom_documents (project_id);
CREATE INDEX idx_sbom_documents_is_latest ON sbom_documents (is_latest) WHERE is_latest = TRUE;
