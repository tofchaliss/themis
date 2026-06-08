CREATE TABLE risk_context (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    component_vulnerability_id UUID NOT NULL UNIQUE REFERENCES component_vulnerabilities(id),
    effective_state TEXT NOT NULL
        CHECK (effective_state IN (
            'open', 'mitigated', 'accepted', 'false_positive', 'not_applicable', 'fixed'
        )),
    priority TEXT NOT NULL DEFAULT 'medium'
        CHECK (priority IN ('critical', 'high', 'medium', 'low', 'informational')),
    risk_score NUMERIC(6, 2),
    triage_notes TEXT,
    triaged_by TEXT,
    triaged_at TIMESTAMPTZ,
    vex_assertion_id UUID REFERENCES vex_assertions(id),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_risk_context_effective_state ON risk_context (effective_state);
