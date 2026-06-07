CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL DEFAULT 'nvd',
    severity TEXT NOT NULL DEFAULT 'unknown',
    cvss_score NUMERIC(4, 1),
    cvss_vector TEXT,
    description TEXT,
    affected_versions TEXT[] NOT NULL DEFAULT '{}',
    fix_versions TEXT[] NOT NULL DEFAULT '{}',
    reference_urls TEXT[] NOT NULL DEFAULT '{}',
    published_at TIMESTAMPTZ,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE component_vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    component_version_id UUID NOT NULL REFERENCES component_versions(id),
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id),
    sbom_document_id UUID NOT NULL REFERENCES sbom_documents(id),
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (component_version_id, vulnerability_id, sbom_document_id)
);
