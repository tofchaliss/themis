-- M5 EB-02: thread the full kernel Envelope through the outbox. Generalize the
-- context-specific subject column (faultline_id -> subject) and add the envelope
-- metadata (source_context, schema_ref, correlation_id) so the relay reads a complete
-- Envelope. The outbox row id already serves as the Envelope id.
ALTER TABLE knowledge_outbox RENAME COLUMN faultline_id TO subject;
ALTER TABLE knowledge_outbox ADD COLUMN source_context TEXT NOT NULL DEFAULT '';
ALTER TABLE knowledge_outbox ADD COLUMN schema_ref     TEXT NOT NULL DEFAULT '';
ALTER TABLE knowledge_outbox ADD COLUMN correlation_id TEXT NOT NULL DEFAULT '';
