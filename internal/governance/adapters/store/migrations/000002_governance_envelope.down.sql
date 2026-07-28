-- Reverse 000002: drop the envelope metadata and restore the context-specific subject name.
ALTER TABLE governance_outbox DROP COLUMN correlation_id;
ALTER TABLE governance_outbox DROP COLUMN schema_ref;
ALTER TABLE governance_outbox DROP COLUMN source_context;
ALTER TABLE governance_outbox RENAME COLUMN subject TO finding_id;
