CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE products (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id UUID NOT NULL REFERENCES products(id),
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (product_id, name)
);

CREATE TABLE product_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id UUID NOT NULL REFERENCES products(id),
    version TEXT NOT NULL,
    release_status TEXT NOT NULL DEFAULT 'draft'
        CHECK (release_status IN ('draft', 'released', 'deprecated')),
    released_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (product_id, version)
);

CREATE TABLE artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_type TEXT NOT NULL
        CHECK (artifact_type IN ('image', 'jar', 'binary', 'firmware', 'other')),
    product_version_id UUID REFERENCES product_versions(id),
    project_id UUID REFERENCES projects(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE images (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id UUID NOT NULL UNIQUE REFERENCES artifacts(id),
    product_id UUID NOT NULL REFERENCES products(id),
    project_id UUID REFERENCES projects(id),
    registry TEXT,
    repository TEXT NOT NULL,
    tag TEXT,
    digest TEXT NOT NULL UNIQUE,
    image_signature TEXT,
    image_signature_format TEXT,
    image_signer_identity TEXT,
    image_signature_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_projects_product_id ON projects (product_id);
CREATE INDEX idx_product_versions_product_id ON product_versions (product_id);
CREATE INDEX idx_artifacts_product_version_id ON artifacts (product_version_id);
CREATE INDEX idx_images_product_id ON images (product_id);
CREATE INDEX idx_images_project_id ON images (project_id);
