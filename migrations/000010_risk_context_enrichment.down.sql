ALTER TABLE risk_context DROP COLUMN IF EXISTS suppression_reason;
ALTER TABLE risk_context DROP COLUMN IF EXISTS vex_status;
ALTER TABLE risk_context DROP COLUMN IF EXISTS raw_severity;

ALTER TABLE risk_context DROP CONSTRAINT IF EXISTS risk_context_effective_state_check;

UPDATE risk_context SET effective_state = 'open' WHERE effective_state = 'detected';
UPDATE risk_context SET effective_state = 'fixed' WHERE effective_state = 'resolved';
UPDATE risk_context SET effective_state = 'accepted' WHERE effective_state = 'accepted_risk';
UPDATE risk_context SET effective_state = 'not_applicable' WHERE effective_state = 'suppressed';

ALTER TABLE risk_context ADD CONSTRAINT risk_context_effective_state_check CHECK (effective_state IN (
    'open', 'mitigated', 'accepted', 'false_positive', 'not_applicable', 'fixed'
));
