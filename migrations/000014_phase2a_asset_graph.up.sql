-- Phase 2a: asset graph entities and exploit records

CREATE TABLE microservices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id UUID NOT NULL REFERENCES products(id),
    name TEXT NOT NULL,
    description TEXT,
    tech_stack JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (product_id, name)
);

CREATE TABLE customers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    contact_email TEXT NOT NULL UNIQUE,
    notification_preferences JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE deployments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    microservice_id UUID NOT NULL REFERENCES microservices(id),
    customer_id UUID NOT NULL REFERENCES customers(id),
    environment TEXT NOT NULL,
    region TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (microservice_id, environment, region, customer_id)
);

CREATE TABLE asset_graph_nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_type TEXT NOT NULL CHECK (node_type IN (
        'CVE', 'CWE', 'Package', 'Product', 'Microservice', 'Deployment', 'Customer'
    )),
    entity_id UUID NOT NULL,
    properties JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (node_type, entity_id)
);

CREATE TABLE asset_graph_edges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    from_node_id UUID NOT NULL REFERENCES asset_graph_nodes(id),
    to_node_id UUID NOT NULL REFERENCES asset_graph_nodes(id),
    edge_type TEXT NOT NULL,
    weight NUMERIC(6, 2) NOT NULL DEFAULT 1.0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (from_node_id, to_node_id, edge_type)
);

CREATE TABLE exploit_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    edb_id TEXT NOT NULL UNIQUE,
    cve_id TEXT,
    exploit_type TEXT,
    published_date DATE,
    title TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_microservices_product_id ON microservices (product_id);
CREATE INDEX idx_deployments_microservice_id ON deployments (microservice_id);
CREATE INDEX idx_deployments_customer_id ON deployments (customer_id);
CREATE INDEX idx_asset_graph_nodes_entity ON asset_graph_nodes (entity_id);
CREATE INDEX idx_exploit_records_cve_id ON exploit_records (cve_id);
