-- C6 (EDR-ESTATE-01 D6): materialize Knowledge's CVE-intrinsic base priority score onto each
-- Finding, updated from the FaultlineEnriched event. It is denormalized read-data (like
-- current_stance), not aggregate state — Governance scales it by the release-scoped blast
-- multiplier (C2). Defaults to 0 so existing Findings and older enriched payloads are safe.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS base_score INT NOT NULL DEFAULT 0;
