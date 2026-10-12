# Frozen test oracles — NOT an operator road

The two files here are the implementations the Go converters in
`internal/evidence/adapters/report` replaced:

| file | was | replaced by |
| --- | --- | --- |
| `cortex_csv_to_scan_report.py` | the Python body of `scripts/cortex-csv-to-scan-report.sh` | `report/cortex.go` |
| `translate_trivy.js` | `translateTrivy` in `cmd/dashboard/static/app.js` (EDR-GUI-01 D16) | `report/trivy.go` |

They live under `testdata/` because they are **test fixtures, not code**: nothing in the
build imports them, no deployment ships them, and no procedure tells an operator to run
them. The one road for converting a vendor report is `POST /api/v1/intake`
(EDR-INTAKE-01 D1/D4) — `scripts/cortex-csv-to-scan-report.sh` now POSTs to it and the
dashboard's upload form does the same.

**They are frozen.** Their output on the corpora in `../cortex/` and `../trivy/` is the
acceptance oracle for the port (D4: "a behavioural equivalence task, not a rewrite"), so
a change here would move the contract instead of meeting it. If one of them ever looks
wrong, the thing to change is the Go converter and the committed goldens beside the
fixtures — and the question to answer first is which of the two is wrong, which is
exactly the question a frozen oracle exists to make askable.

**This is not a second converter.** TESTING.md's rule — *a second converter is a defect,
not a convenience*; the 2026-09-10 case traced 579 permanently-unclearable occurrences to
an ad-hoc variant — is about the roads an operator can take with real data. These files
are on no such road: they read committed fixtures in a test, and the reason they are kept
at all is that deleting them would leave the Go converter comparing itself against
goldens it could have produced.

## How the tests use them

`TestCortexConvertMatchesScriptOracle` and `TestTrivyConvertMatchesJSOracle`
compare the Go converter against the committed `*.golden.json` **always**, and against
these oracles run live wherever `python3` / `node` exist. Where an interpreter is missing
the live run logs a note and steps aside — the goldens are what keep the gate from
evaporating on such a host (CI is one: `make check-ci` provisions neither interpreter) —
and where it exists, the live run is what keeps the goldens honest.

Regenerate the goldens FROM THE ORACLES, never from the code under test:

```sh
# needs python3 (Cortex) and node (Trivy) on PATH
go test ./internal/evidence/adapters/report/ -run TestUpdateGoldens -update-goldens
```
