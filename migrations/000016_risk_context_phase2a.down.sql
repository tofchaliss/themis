ALTER TABLE risk_context DROP CONSTRAINT IF EXISTS risk_context_effective_state_check;
ALTER TABLE risk_context ADD CONSTRAINT risk_context_effective_state_check CHECK (effective_state IN (
    'detected',
    'suppressed',
    'confirmed',
    'in_triage',
    'accepted_risk',
    'false_positive',
    'resolved'
));

ALTER TABLE risk_context
    DROP COLUMN IF EXISTS upstream_vex_coverage,
    DROP COLUMN IF EXISTS blast_radius_score,
    DROP COLUMN IF EXISTS deterministic_level,
    DROP COLUMN IF EXISTS exploit_public,
    DROP COLUMN IF EXISTS kev_listed,
    DROP COLUMN IF EXISTS epss_score;
