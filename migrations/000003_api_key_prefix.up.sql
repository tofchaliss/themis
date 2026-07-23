-- Add an indexed plaintext key prefix so authentication can look up the single
-- candidate key by prefix instead of bcrypt-scanning every active key. Legacy
-- keys (created before this column) keep a NULL prefix and use the fallback path.
ALTER TABLE api_keys ADD COLUMN key_prefix TEXT;
CREATE INDEX idx_api_keys_key_prefix ON api_keys (key_prefix) WHERE key_prefix IS NOT NULL;
