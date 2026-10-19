# Grype fixtures (GUI-15)

`sample.input.json` is a hand-built `grype … -o json` document covering: a GHSA-keyed match with
a related CVE and both a 2.0 and a 3.1 CVSS entry; a CVE-keyed match with two fix versions; an rpm
match with no purl, no fix and no CVSS; a match with no flaw id (skipped); a null element
(skipped); and a GHSA match whose related ids carry no CVE, with a zero 3.0 score.

`sample.golden.json` is the converter's own output, frozen on the day the dialect was added: there
was no earlier implementation to be byte-equal with, so the golden IS the fingerprint contract.
