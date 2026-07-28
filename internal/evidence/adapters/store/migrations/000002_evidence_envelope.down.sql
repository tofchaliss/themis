-- Reverse 000002: drop the envelope metadata and restore the context-specific subject name.
ALTER TABLE evidence_outbox DROP COLUMN correlation_id;
ALTER TABLE evidence_outbox DROP COLUMN schema_ref;
ALTER TABLE evidence_outbox DROP COLUMN source_context;
ALTER TABLE evidence_outbox RENAME COLUMN subject TO evidence_id;
