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
