-- EDR-REMEDIATION-01 D6: when an evaluated SBOM first no longer carried an open Finding. A
-- projection column for the time-to-remediation measure, set by the upload outcome and cleared
-- when an SBOM carries the Finding again. It decides nothing: the Finding stays open with its
-- Position (R-B), and the measure counts it only once a person decided afterwards (Q4).
ALTER TABLE findings ADD COLUMN IF NOT EXISTS absent_since TIMESTAMPTZ;
