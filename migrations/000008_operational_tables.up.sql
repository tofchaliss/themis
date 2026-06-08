CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE notification_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    channel TEXT NOT NULL CHECK (channel IN ('email', 'slack', 'webhook')),
    destination TEXT NOT NULL,
    filter JSONB NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE cve_watch_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id TEXT NOT NULL,
    product_id UUID REFERENCES products(id),
    project_id UUID REFERENCES projects(id),
    status TEXT NOT NULL DEFAULT 'new'
        CHECK (status IN ('new', 'acknowledged', 'resolved', 'ignored')),
    details JSONB NOT NULL DEFAULT '{}',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id UUID,
    details JSONB NOT NULL DEFAULT '{}',
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE ingestion_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    payload JSONB NOT NULL DEFAULT '{}',
    error_message TEXT,
    attempts INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE INDEX idx_api_keys_key_hash ON api_keys (key_hash);
CREATE INDEX idx_notification_rules_event_type ON notification_rules (event_type);
CREATE INDEX idx_cve_watch_findings_cve_id ON cve_watch_findings (cve_id);
CREATE INDEX idx_cve_watch_findings_product_id ON cve_watch_findings (product_id);
CREATE INDEX idx_audit_log_occurred_at ON audit_log (occurred_at);
CREATE INDEX idx_ingestion_jobs_status ON ingestion_jobs (status);
