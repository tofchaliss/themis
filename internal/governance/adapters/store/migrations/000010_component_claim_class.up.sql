-- EDR-CORRELATION-01 D3: why a component matched, not merely that it did.
--
-- A distro module-stream advisory rebuilds every RPM in the stream and lists them all as affected.
-- Read as N vulnerability claims, that records a CPython flaw as a vulnerability of
-- python3-pyyaml. Knowledge now classifies each match at correlation and ships the verdict.
--
-- DEFAULT '' is `unknown`, which every consumer treats as `carrier` — so existing rows keep
-- exactly their present behaviour and no backfill is required. A gap in evidence must never hide
-- a live vulnerability.
ALTER TABLE finding_components ADD COLUMN IF NOT EXISTS claim_class TEXT NOT NULL DEFAULT '';
