-- Δ4a fix (measured live 2026-08-26): the capture context is REDACTED before it is written, and
-- the redactor rewrites substrings (purls, secret k/v, emails) of the marshaled JSON — which
-- produces a string that is no longer valid JSON. A JSONB column silently REJECTS that insert,
-- and the capturer swallows the error by contract (best-effort), so capture wrote NOTHING
-- whenever the context held redactable content (a real Finding always does: component purls).
--
-- The fix: the redacted columns are TEXT (opaque, post-redaction strings), not JSONB. Redaction
-- is an OUTPUT boundary; the stored form is a scrubbed string, not a queryable document. The
-- harness-owned columns (expected_json, results_json) are marshaled in-process and never
-- redacted, so they stay JSONB.
ALTER TABLE invocation_log ALTER COLUMN context_json TYPE TEXT;
ALTER TABLE invocation_log ALTER COLUMN output_json  TYPE TEXT;
ALTER TABLE golden_entries ALTER COLUMN context_json TYPE TEXT;
