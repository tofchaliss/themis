# Nessus fixtures (EDR-INTAKE-01, 2026-10-24 amendment)

`sample.input.nessus` is a hand-built `.nessus` (NessusClientData_v2) export. Every address,
host name and MAC is from a documentation range (`192.0.2.0/24`, `example.test`,
`00:00:5e:00:53:xx`); no real export is committed (N8). It covers:

- host 1, timed by `HOST_END_TIMESTAMP`:
  - a vendor advisory check with 2 CVEs × 2 package lines and `Should be` fixes (4 findings);
  - a vendor advisory check with an epoch package, `risk_factor` `None`, and one package line
    that cannot be split (1 finding, 1 skipped);
  - an upstream version check (`Misc.`) with 3 CVEs (3 skipped);
  - a local check with a CVE but no package line (1 skipped);
  - an informational plugin with no CVE (not counted);
- host 2, timed only by `HOST_END`, repeating one advisory check (1 finding, kept — the
  converter does not merge hosts).

`sample.golden.json` is the converter's own output, frozen on the day the dialect was added:
there was no earlier implementation to be byte-equal with, so the golden IS the fingerprint
contract.

## 2026-10-26 amendment: the package list (P1–P9) and the CSV (C1–C6)

`inventory.input.nessus` is a hand-built export for the SBOM road (`nessus-inventory@2`),
documentation ranges only. Plugin 22869 ("Software Enumeration (SSH)") on:

- host 1, RHEL 8.10: four Red Hat packages (one with epoch 1, one module build), one package
  from a made-up vendor, one from Fedora/EPEL, and `gpg-pubkey`, which does not split
  (3 skipped);
- host 2, RHEL 8.10: the same `zlib` (collapses) and a NEWER kernel (kept: real drift);
- host 3, Windows: one package line (skipped — the OS is not mapped).

`inventory.golden.json` is the CycloneDX document it produces: 5 components, 4 skipped.

`sample.input.csv` is a hand-built Nessus CSV with the real export's column order, for the
report road (`nessus-csv@2`): an advisory row with two package lines, one with an epoch and
`Risk` `None`, one whose package line does not split, two upstream version checks and an
informational row with no CVE. `sample.csv.golden.json` is its output for
`observed_at=2026-10-15T21:30:00Z`: 3 kept of 6 considered.

## 2026-10-27 amendment: hand-installed software (H1–H5)

Host 1 of `inventory.input.nessus` also carries detection plugins: Tomcat under `/var/lib`
(CPE, no table line → `pkg:generic`), a JDBC JAR at two paths (one Maven component, two
`themis:install-path` properties), OpenSSL blocks with package marks (not filed), an unmarked
vim under `/usr` (undecidable, not filed), an agent whose RPM is on the host (rule 4, not
filed), a tool with no CPE (no identity, not filed), and the Python / gem list plugins with one
install under `/usr` (not filed) and one under `/opt` each (`pkg:pypi`, `pkg:gem`). The golden
now holds 9 components, 4 skipped, 4 unmanaged.

`sample.input.nessus` gains a Tomcat detection plus its class C check (2 CVEs, kept — H3) and a
vim check under `/usr` (skipped): 8 kept of 14 considered. `sample.input.csv` gains the same
Tomcat pair as rows: 4 kept of 7 considered.
