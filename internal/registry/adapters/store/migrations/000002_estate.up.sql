-- Registry estate graph (EDR-ESTATE-01 C1): the enterprise topology hanging off Product —
-- Product → Microservice → Deployment → Customer. Foreign keys enforce membership at the
-- database, mirroring the domain invariants. Populated via CRUD (a CMDB-sync ACL is a
-- follow-up); traversed to compute a release's blast radius (unique customers reached).

CREATE TABLE IF NOT EXISTS customers (
    id   TEXT PRIMARY KEY,   -- opaque, context-owned identity
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS microservices (
    id         TEXT PRIMARY KEY,
    product_id TEXT NOT NULL REFERENCES products (id),   -- every Microservice ∈ one Product
    name       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_microservices_product ON microservices (product_id);

CREATE TABLE IF NOT EXISTS deployments (
    id              TEXT PRIMARY KEY,
    microservice_id TEXT NOT NULL REFERENCES microservices (id),   -- where a Microservice runs
    customer_id     TEXT NOT NULL REFERENCES customers (id),       -- who it serves (the impact leaf)
    environment     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_deployments_microservice ON deployments (microservice_id);
CREATE INDEX IF NOT EXISTS idx_deployments_customer ON deployments (customer_id);
