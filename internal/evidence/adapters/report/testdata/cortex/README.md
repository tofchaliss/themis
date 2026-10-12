# Cortex fixture corpus — the D4 equivalence oracle

These files are the acceptance oracle for `internal/evidence/adapters/report`'s Cortex
converter. EDR-INTAKE-01 D4 makes the port a **behavioural equivalence task, not a
rewrite**: the Python conversion `scripts/cortex-csv-to-scan-report.sh` carried is the
implementation being replaced, its output on this corpus is the contract, and the Go
converter must reproduce it **byte for byte** (tasks.md 1.4 gated 4.2).

Since 4.2 the script is a **thin wrapper that POSTs to intake** and that Python is
frozen at [`../oracle/cortex_csv_to_scan_report.py`](../oracle/README.md) — a test
fixture on no operator road, moved verbatim so the goldens below keep an oracle that is
not the code under test.

Byte equality is not cosmetic. Evidence's dedup key is the SHA-256 of the **filed**
document, so a converter that re-serializes the same findings differently makes every
post-cutover re-submission a brand-new evidence document — a duplicate scan of the same
image, with nothing to show it was a re-serialization rather than a re-scan. That is
KN-SCAN-4's shape arriving through a new door.

## Regenerating the goldens

Each `*.golden.json` is the **oracle's** output, never the Go converter's:

```sh
# needs python3 on PATH (the Cortex oracle is CPython; the Trivy half needs node)
go test ./internal/evidence/adapters/report/ -run TestUpdateGoldens -update-goldens
```

A golden regenerated from the code under test would prove nothing — if one ever needs
updating, the question to answer first is whether the **oracle's** behaviour changed.

**Environment.** The live oracle run needs `python3`; the Trivy half needs
`node`. Where an interpreter is missing the live run logs a note and steps aside, and
the **committed goldens are the authoritative oracle** — they are what keeps the gate
from quietly evaporating on such a host (CI is one: `make check-ci` sets up neither
interpreter). Where the interpreters exist, `TestCortexConvertMatchesScriptOracle`
runs the oracle itself, which is what keeps the goldens honest. Both comparisons
assert the same bytes, so a divergence fails whichever halves are available.

## The inputs, and what each one is for

| file | what it proves |
| --- | --- |
| `slice.csv` | A real-shaped export: `cve_description` quoted and spanning physical lines (RFC 4180 — the 20.1.0.0-125 export is 1264 physical lines carrying 557 logical rows, and the pre-2026-09-10 line-splitting implementation shredded every such row). Also an `Unknown` severity, an empty `cvss_score` and an unparseable one, and `fix_versions` split on `;`. |
| `app-el8.csv` | **KN-SCAN-3b.** An `APP` row whose purl has no `pkg:` prefix (so no ecosystem) and whose version carries an RPM release marker, which must infer `rpm`; an `APP` row with no marker, which must stay blank. Measured 2026-09-10: 87 httpd findings with a blank ecosystem, every one permanently un-clearable. |
| `multi-fix.csv` | `fix_versions` across **both** separators, with padding and an empty trailing piece. |
| `nopurl.csv` | **EDR-IDENTITY-01 D6 abstention.** A row with no purl keeps an EMPTY purl — never an invented one, because a plausible identity correlates and an abstention does not. Plus the converter's one skip condition twice (no CVE id; neither purl nor name). |
| `nonascii.csv` | `json.dumps` defaults to `ensure_ascii=True`, so non-ASCII package names leave as `uXXXX` escapes. No amount of ASCII fixtures would have caught this, and Go's encoders do the opposite by default. |
| `no-observed.csv` | The **ordinary** Cortex CSV: no `last_observed` column, which is why D3 says the timestamp is "absent in the CSV". With nothing supplied this is `observed_at_underivable`, never stamped with the upload time. |
| `2026-10-05-array.json` | **The regression this change exists for.** The array-shaped Cortex export: on 2026-10-05 one of these was filed raw because no JSON road existed, and it halted Knowledge's evidence stream for 31 hours on the poison event (GUI-16b). Shape-faithful to the real export; the live 427-element body is re-run on the estate in tasks.md 5.1. |
| `2026-10-05-array.csv` | The **CSV projection** of that array — the GUI-16b shim (project the fields the oracle reads to CSV, joining array-valued fields on `;`, nulling absent ones), which is how the array body gets an oracle at all: the Python reads CSV only. `TestCortexJSONEqualsCSVProjection` asserts the two containers produce ONE document, so the JSON side is byte-equal to the oracle through the CSV side. That is tasks.md 5.2 at unit level. |

`element 47` — the real export with element 47 structurally broken and element 0 valid
(EDR-INTAKE-01 D5b, tasks.md 7.5) — is **not** here: it is a Group 7 fixture and needs the
real file with its provenance note. The structural shape it guards is covered meanwhile by
`TestCortexJSONStructuralRefusals/a_later_element_carries_no_Cortex_field_set`.
