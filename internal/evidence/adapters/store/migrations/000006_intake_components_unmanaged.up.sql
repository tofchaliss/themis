-- `components_unmanaged` (EDR-INTAKE-01, 2026-10-27 H5): the hand-installed components a
-- converted SBOM filed beside the packages — software no package manager owns (a Tomcat under
-- /var/lib, an application's JARs under /opt), found by the scanner's detection plugins under
-- the H1 rule. Reported beside `components` so a host with a hand-installed Tomcat and one
-- without do not look alike.
--
-- NOT NULL DEFAULT 0: no existing receipt filed such a component, so 0 is the true value.
ALTER TABLE intake_receipts ADD COLUMN components_unmanaged INTEGER NOT NULL DEFAULT 0;
