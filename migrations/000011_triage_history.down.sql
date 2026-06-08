DROP TABLE IF EXISTS triage_history;

ALTER TABLE risk_context DROP COLUMN IF EXISTS accepted_until;
ALTER TABLE risk_context DROP COLUMN IF EXISTS assigned_to;

ALTER TABLE vex_assertions DROP COLUMN IF EXISTS component_purl;

ALTER TABLE vex_documents DROP COLUMN IF EXISTS issuer;
ALTER TABLE vex_documents DROP COLUMN IF EXISTS source;
