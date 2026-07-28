-- Reverse 000002: drop the envelope metadata and restore the context-specific subject name.
ALTER TABLE knowledge_outbox DROP COLUMN correlation_id;
ALTER TABLE knowledge_outbox DROP COLUMN schema_ref;
ALTER TABLE knowledge_outbox DROP COLUMN source_context;
ALTER TABLE knowledge_outbox RENAME COLUMN subject TO faultline_id;
