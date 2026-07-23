-- Record the client source IP on audit entries (previously captured in the
-- domain model but dropped at insert). Nullable: async/system actions have none.
ALTER TABLE audit_log ADD COLUMN source_ip INET;
