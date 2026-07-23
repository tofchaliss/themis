-- Registry context schema (EDR-KERNEL-01 D1): the Product → Project → Release
-- structural identity hierarchy. Identity + structure only — no security state
-- (Governance owns that, keyed to a Release it references). The registry owns its own
-- tables (Book III §3.5), separate from the top-level migrations/ and other contexts.

CREATE TABLE IF NOT EXISTS products (
    id   TEXT PRIMARY KEY,   -- opaque, context-owned identity
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
    id         TEXT PRIMARY KEY,
    product_id TEXT NOT NULL REFERENCES products (id),   -- every Project ∈ one Product
    name       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_projects_product ON projects (product_id);

CREATE TABLE IF NOT EXISTS releases (
    id         TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects (id),   -- every Release ∈ one Project
    version    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_releases_project ON releases (project_id);
