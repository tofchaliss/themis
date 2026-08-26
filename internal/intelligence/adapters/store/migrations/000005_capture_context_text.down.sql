ALTER TABLE golden_entries ALTER COLUMN context_json TYPE JSONB USING context_json::jsonb;
ALTER TABLE invocation_log ALTER COLUMN output_json  TYPE JSONB USING output_json::jsonb;
ALTER TABLE invocation_log ALTER COLUMN context_json TYPE JSONB USING context_json::jsonb;
