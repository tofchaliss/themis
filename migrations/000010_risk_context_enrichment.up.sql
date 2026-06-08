ALTER TABLE risk_context DROP CONSTRAINT IF EXISTS risk_context_effective_state_check;

UPDATE risk_context SET effective_state = 'detected' WHERE effective_state = 'open';
UPDATE risk_context SET effective_state = 'resolved' WHERE effective_state = 'fixed';
UPDATE risk_context SET effective_state = 'accepted_risk' WHERE effective_state = 'accepted';
UPDATE risk_context SET effective_state = 'suppressed' WHERE effective_state = 'not_applicable';

ALTER TABLE risk_context ADD CONSTRAINT risk_context_effective_state_check CHECK (effective_state IN (
    'detected',
    'suppressed',
    'confirmed',
    'in_triage',
    'accepted_risk',
    'false_positive',
    'resolved'
));

ALTER TABLE risk_context ADD COLUMN IF NOT EXISTS raw_severity TEXT;
ALTER TABLE risk_context ADD COLUMN IF NOT EXISTS vex_status TEXT;
ALTER TABLE risk_context ADD COLUMN IF NOT EXISTS suppression_reason TEXT;

UPDATE risk_context rc
SET raw_severity = COALESCE(v.severity, 'unknown')
FROM component_vulnerabilities cv
JOIN vulnerabilities v ON v.id = cv.vulnerability_id
WHERE rc.component_vulnerability_id = cv.id
  AND rc.raw_severity IS NULL;
