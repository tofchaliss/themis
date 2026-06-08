CREATE TABLE components (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    purl TEXT NOT NULL UNIQUE,
    component_type TEXT,
    ecosystem TEXT,
    name TEXT NOT NULL,
    namespace TEXT,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE component_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    component_id UUID NOT NULL REFERENCES components(id),
    version TEXT NOT NULL,
    sbom_document_id UUID NOT NULL REFERENCES sbom_documents(id),
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    licenses TEXT[] NOT NULL DEFAULT '{}',
    direct_dependency BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (component_id, version, sbom_document_id)
);

CREATE TABLE dependency_relationships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sbom_document_id UUID NOT NULL REFERENCES sbom_documents(id),
    from_component_version_id UUID NOT NULL REFERENCES component_versions(id),
    to_component_version_id UUID NOT NULL REFERENCES component_versions(id),
    relationship_type TEXT NOT NULL DEFAULT 'depends_on',
    scope TEXT NOT NULL DEFAULT 'runtime',
    depth INT NOT NULL DEFAULT 1 CHECK (depth >= 1)
);

CREATE INDEX idx_component_versions_component_id ON component_versions (component_id);
CREATE INDEX idx_component_versions_sbom_document_id ON component_versions (sbom_document_id);
CREATE INDEX idx_dependency_relationships_sbom_document_id ON dependency_relationships (sbom_document_id);
