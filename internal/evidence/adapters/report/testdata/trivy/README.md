# Trivy fixture corpus — the D4 equivalence oracle

The oracle for this dialect is `translateTrivy` in `cmd/dashboard/static/app.js`
(EDR-GUI-01 D16), the in-browser translator the Go converter replaces. The test
**extracts the function from app.js and runs it under node** rather than keeping a copy:
a copy would be a second converter, and TESTING.md is explicit that a second converter
is a defect, not a convenience. Extracting it means the test fails the day the two
diverge — which is the only thing that makes "one converter per dialect" checkable
before the browser copy is deleted in M3.

The document compared is `JSON.stringify({findings: out.findings})` — the expression
app.js actually uploads, not the translator's return value — so the bytes under test are
the bytes that were filed. See the Cortex README for why byte equality is load-bearing.

## Regenerating the goldens

```sh
# needs node on PATH (and bash + python3 for the Cortex half of the same test)
go test ./internal/evidence/adapters/report/ -run TestUpdateGoldens -update-goldens
```

Committed so the gate survives a host with no `node` — on such a host the live
extraction steps aside with a log note and the **committed goldens are the
authoritative oracle**. Where `node` exists the extraction run keeps them honest. The
regeneration test refuses to write anything if the interpreter it needs is missing,
rather than writing this package's own output over the oracle's.

## The inputs

| file | what it proves |
| --- | --- |
| `sample.input.json` | Two results with different `Type`s (one unmapped, which passes through — KN-SCAN-3 is the server-side net), a vulnerability with no `VulnerabilityID` and a `null` element (both counted skips, never fatal), an empty `FixedVersion`, a `CVSS` block with no `nvd` entry, a result with no `Vulnerabilities` at all, and 7-digit fractional seconds on `CreatedAt` (truncated to milliseconds, because `toISOString` writes exactly three). |
| `complex.input.json` | The mapped ecosystems (`jar`→`maven`, `gomod`→`golang`), a result with **no** `Type`, a non-UTC `CreatedAt`, an integer `V3Score` (`10`, which JS writes without a decimal point), a zero `V3Score`, a non-ASCII package name (JSON.stringify emits raw UTF-8 — the opposite of the Cortex road), and `FixedVersion: "2.15.0, 2.12.2"` taken **verbatim** rather than split, because the translator does not split it and this is a port. |
| `nocreated.input.json` | The one behaviour deliberately **not** ported. The browser fell back to `new Date()` and said so in the file note; D3 forbids it, because a stamped-fresh report re-uploaded tomorrow is a second scan of the same image. This fixture has no golden — the JS oracle's output for it is not deterministic, which is the whole point — and is asserted as `observed_at_underivable`, then as a success under a supplied timestamp. |
