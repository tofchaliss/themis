CREATE TABLE intelligence_signals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    component_vulnerability_id UUID NOT NULL REFERENCES component_vulnerabilities(id),
    signal_type TEXT NOT NULL,
    source TEXT NOT NULL,
    confidence NUMERIC(4, 3) CHECK (confidence >= 0 AND confidence <= 1),
    summary TEXT,
    details JSONB NOT NULL DEFAULT '{}',
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE runtime_exposures (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    component_vulnerability_id UUID NOT NULL REFERENCES component_vulnerabilities(id),
    exposure_type TEXT NOT NULL,
    environment TEXT,
    is_exposed BOOLEAN NOT NULL DEFAULT FALSE,
    evidence JSONB NOT NULL DEFAULT '{}',
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE remediation_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    component_vulnerability_id UUID NOT NULL REFERENCES component_vulnerabilities(id),
    action_type TEXT NOT NULL,
    description TEXT,
    target_version TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'in_progress', 'completed', 'blocked')),
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_intelligence_signals_component_vuln_id ON intelligence_signals (component_vulnerability_id);
CREATE INDEX idx_runtime_exposures_component_vuln_id ON runtime_exposures (component_vulnerability_id);
CREATE INDEX idx_remediation_actions_component_vuln_id ON remediation_actions (component_vulnerability_id);
