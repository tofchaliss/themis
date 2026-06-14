ALTER TABLE risk_context
    ADD COLUMN epss_score NUMERIC(6, 5),
    ADD COLUMN kev_listed BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN exploit_public BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN deterministic_level TEXT,
    ADD COLUMN blast_radius_score NUMERIC(4, 2) NOT NULL DEFAULT 1.0,
    ADD COLUMN upstream_vex_coverage TEXT
        CHECK (upstream_vex_coverage IN ('covered', 'not_covered', 'purl_mismatch'));

ALTER TABLE risk_context DROP CONSTRAINT IF EXISTS risk_context_effective_state_check;
ALTER TABLE risk_context ADD CONSTRAINT risk_context_effective_state_check CHECK (effective_state IN (
    'detected',
    'suppressed',
    'confirmed',
    'in_triage',
    'accepted_risk',
    'false_positive',
    'resolved',
    'not_affected'
));
