-- `components_skipped` (EDR-INTAKE-01, 2026-10-26 P4): the package lines a converted SBOM
-- left out because no identity could be read for them — a Nessus export's packages from
-- another vendor, or from an OS Themis does not map. Reported beside `components` so
-- "1249 of 1249" and "1249 of 1291" do not look alike (KN-SCAN-OBS-1's rule, applied to an
-- inventory).
--
-- NOT NULL DEFAULT 0: every existing receipt is either a report or an SBOM filed as
-- submitted, and neither skipped a component, so 0 is the true value, not a placeholder.
ALTER TABLE intake_receipts ADD COLUMN components_skipped INTEGER NOT NULL DEFAULT 0;
