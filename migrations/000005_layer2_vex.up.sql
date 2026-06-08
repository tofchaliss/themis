CREATE TABLE vex_documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sbom_document_id UUID NOT NULL REFERENCES sbom_documents(id),
    sbom_checksum TEXT NOT NULL,
    checksum_sha256 TEXT NOT NULL,
    format TEXT NOT NULL CHECK (format IN ('cyclonedx', 'csaf', 'openvex')),
    spec_version TEXT,
    supplier_identity TEXT,
    signature TEXT,
    signature_format TEXT,
    signer_identity TEXT,
    signature_verified BOOLEAN NOT NULL DEFAULT FALSE,
    trust_status TEXT NOT NULL DEFAULT 'unsigned'
        CHECK (trust_status IN ('verified', 'unverified', 'failed', 'unsigned')),
    raw_document JSONB NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (sbom_checksum, checksum_sha256)
);

CREATE TABLE vex_assertions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vex_document_id UUID NOT NULL REFERENCES vex_documents(id),
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id),
    component_version_id UUID REFERENCES component_versions(id),
    status TEXT NOT NULL
        CHECK (status IN ('not_affected', 'affected', 'fixed', 'under_investigation')),
    justification TEXT,
    impact_statement TEXT,
    action_statement TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vex_documents_sbom_document_id ON vex_documents (sbom_document_id);
CREATE INDEX idx_vex_assertions_vex_document_id ON vex_assertions (vex_document_id);
CREATE INDEX idx_vex_assertions_vulnerability_id ON vex_assertions (vulnerability_id);
