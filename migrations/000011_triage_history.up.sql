ALTER TABLE vex_documents ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'vendor'
    CHECK (source IN ('vendor', 'upstream', 'manual', 'themis_generated'));
ALTER TABLE vex_documents ADD COLUMN IF NOT EXISTS issuer TEXT;

ALTER TABLE vex_assertions ADD COLUMN IF NOT EXISTS component_purl TEXT;

ALTER TABLE risk_context ADD COLUMN IF NOT EXISTS assigned_to TEXT;
ALTER TABLE risk_context ADD COLUMN IF NOT EXISTS accepted_until TIMESTAMPTZ;

CREATE TABLE triage_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    component_vulnerability_id UUID NOT NULL REFERENCES component_vulnerabilities(id),
    decision TEXT NOT NULL
        CHECK (decision IN ('false_positive', 'accepted_risk', 'confirmed', 'resolved', 'escalate')),
    justification TEXT NOT NULL,
    actor TEXT NOT NULL,
    accepted_until TIMESTAMPTZ,
    assigned_to TEXT,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_triage_history_finding_recorded
    ON triage_history (component_vulnerability_id, recorded_at DESC);
