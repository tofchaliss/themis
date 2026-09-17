-- Component retirement (KN-SCAN-4(b)).
--
-- A recorded occurrence can turn out not to denote an additional component: a scanner report
-- named one under a raw identifier while the SBOM path had already recorded the same component
-- under its canonical purl. Measured on MRF 2026-09-17 -- 87 such rows, all one component, and
-- in 87 of 87 cases the canonical row ALREADY existed on the same (release, card).
--
-- Retirement is a PROJECTION change, not an erasure. The row stays, so the audit trail keeps
-- every occurrence Themis ever recorded and "we retired this" stays distinguishable from "this
-- never happened" -- the same reasoning that makes a cleared verdict a recorded state rather
-- than a deleted row (EDR-VERDICT-01 D2), and that rejected DELETE for the 2026-09-10 repair.
--
-- NULL means active, which is every existing row: retirement is asserted, never inferred.
ALTER TABLE faultline_matches ADD COLUMN IF NOT EXISTS retired_at TIMESTAMPTZ;

-- The sweeps filter on it, so they read it alongside the stamps they already scan.
CREATE INDEX IF NOT EXISTS idx_faultline_matches_active
    ON faultline_matches (faultline_id) WHERE retired_at IS NULL;
