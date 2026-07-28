-- Reverse 000002: drop the envelope metadata and restore the context-specific subject name.
ALTER TABLE communication_outbox DROP COLUMN correlation_id;
ALTER TABLE communication_outbox DROP COLUMN schema_ref;
ALTER TABLE communication_outbox DROP COLUMN source_context;
ALTER TABLE communication_outbox RENAME COLUMN subject TO publication_id;
