# EDR-INTAKE-01 — Report intake: one REST door for SBOMs and vulnerability reports

Status: **PROPOSED 2026-10-09** — written against a measured incident (below). Supersedes nothing;
**amends** EDR-EVIDENCE-01 D2/D4 (what the border validates) and **resolves** GUI-16's deferred
option (c), which was marked *stop-and-ask* precisely so this document would exist before anyone
admitted a non-JSON body.

## Why now

The current road is a shell script (`scripts/gf-upload-sbom.sh`) driving four REST calls across two
services, plus a second script (`scripts/cortex-csv-to-scan-report.sh`) the operator must remember
to run first. On 2026-10-05 an operator skipped the second one, because their Cortex export was
**JSON** and every documented JSON road assumed Trivy. Themis accepted the raw vendor array —
`json.Valid` is the whole of the scanner-report border check — stored it immutably, and **halted
Knowledge's evidence stream for 31 hours** on the poison event (EDR-EVENTBUS-01 D8). Converting the
same export through the maintained script later produced **427 of 427 findings**: the pipeline was
never the problem. The border was, and so was the number of steps a human had to get right.

Three facts from that incident shape every decision here:

1. **A document no consumer can read must not become evidence.** It is immutable once filed
   (CON-0007), so the border is the only place to refuse it. This is parity gap **E1**.
2. **The operator's only feedback was a renderer on another screen**, after the immutable write.
   "The upload failed" and "the upload succeeded and broke the pipeline" looked identical.
3. **The slow part is not the upload.** `Register` never correlates (`register.go:115` parses for
   `KindSBOM` only); correlation is Knowledge's, already asynchronous over the bus. What a client
   cannot do today is learn when the work it triggered has finished.

## Decisions

### D1 — One intake endpoint, owned by Evidence; the client's step count drops to one

`POST /api/v1/intake` on the Evidence node (`:8081`) accepts an SBOM or a vulnerability report,
validates it, converts it when needed, and files it. Evidence owns it because Evidence owns the
border and already holds a read seam onto Registry (`cmd/evidence/main.go:103`, the registry-backed
`SubjectRef`, legal because the composition root may wire both rings and the `registry` schema
co-locates in the `evidence` database).

*Rejected:* a new intake service (a whole node to move bytes 30cm, and a new deployment unit for
every operator); putting it on Registry (Registry owns identity, not documents); leaving it in the
script (the script is the thing that failed — a step a human can forget is not a contract).

`POST /api/v1/evidence` **stays** exactly as it is: the raw, release-id-only, JSON-only door that
the dashboard and the existing scripts use. Intake is additive. Nothing that works today changes.

### D2 — CSV is a request encoding, never an evidence document

A `text/csv` body is accepted by intake, converted **server-side**, and what is filed as Evidence is
the **curated JSON**. The CSV never reaches the document store, so Evidence's document stays a JSON
string, the trust gate keeps `json.Valid`, and CON-0007 is untouched. GUI-16 option (c) said
admitting non-JSON "changes the evidence contract and the domain model" — and it would have, at the
*document* layer. At the *request* layer it changes neither.

The honest cost, recorded rather than hidden: **the filed evidence is a derivative of what the
operator held, and Themis does not retain the original.** Provenance therefore records, as
**separate fields** — one concept per field, because `converted_by = "cortex@1"` overloads dialect,
tool and version into a string nobody can query:

| field | meaning |
| --- | --- |
| `source_digest` | SHA-256 of the exact submitted bytes |
| `source_format` | the identified input dialect (`cortex-json`, `cortex-csv`, `trivy`, `curated`) |
| `source_media_type` | the `Content-Type` the submission arrived with |
| `converter_id` | which converter ran (`cortex`), or empty for a pass-through |
| `converter_version` | its version (`3`), bumped whenever output could change |
| `conversion_result_digest` | SHA-256 of the curated output = the filed document's fingerprint |
| `observed_at` + `observed_at_source` | the resolved observation time and where it came from (`source_data` \| `caller`) |
| `without_sbom` | D6's override was used |

**Provenance is verifiable-by-digest, not reconstructable.** If the operator still holds the
submitted file, `source_digest` proves it is the one Themis converted; if they do not, the original
is gone and no field here brings it back. The earlier draft of this decision said "reconstructable",
which contradicted this EDR's own honest-limits section — corrected 2026-10-09 on review. An estate
that must retain the vendor artifact verbatim needs a separate decision (raw-artifact retention),
not a stronger reading of this one. A client that wants the original filed byte-for-byte uses
`POST /evidence` with its own conversion, as today.

### D3 — Conversion is deterministic, and the idempotency identity is the SOURCE, not the output

Content addressing is what makes a re-upload dedup instead of filing a duplicate scan. Two things
can destroy that, and the second was missed in this EDR's first draft.

**Determinism of the conversion itself.** `observed_at` is **derived from the submitted data** (for
Cortex, `max(last_observed)` — epoch **milliseconds** in the JSON export, absent in the CSV), or
supplied by the caller, and **never defaulted to `now`**. A report with no derivable timestamp and
none supplied is **refused** (`observed_at_underivable`), not stamped: a stamped-fresh report
re-uploaded tomorrow is a second scan of the same image and the operator cannot tell. Conversion is
a pure function of `(bytes, observed_at)` — asserted by a property test, not by convention.

**But purity in `(bytes, observed_at)` is not enough**, because the output also depends on the
converter's own rules:

```text
curated = converter[version](source bytes, observed_at)
```

Verified against the implementation (`store.go:73` — `ON CONFLICT (fingerprint) DO NOTHING`, and
`trust.go:51` — `NewContentFingerprint(a.Raw)` over the **filed** bytes): Evidence's dedup key is
the SHA-256 of the *curated document*, globally, not scoped to release. So **a converter upgrade
that changes output by one byte makes the same source file a brand-new evidence document** — a
duplicate scan of the same image, with no way for anyone to see it was a re-conversion rather than a
re-scan. That is KN-SCAN-4's shape arriving through a new door, and the first draft of this EDR did
not address it at all.

**Therefore, for CONVERTED submissions the idempotency identity is
`(source_digest, release_id, observed_at_resolved)`, checked BEFORE conversion runs.** The intake
looks up whether these exact submitted bytes were already filed against this release at this
observation time; if so it returns the existing `evidence_id` with `created=false`, **without
reconverting**. Pass-through (already-curated) submissions keep the existing content-fingerprint
identity, because there the source *is* the document.

The five questions this answers, each stated so no implementer has to infer it:

| question | answer |
| --- | --- |
| What is the idempotency key? | converted: `(source_digest, release_id, observed_at_resolved)`. Pass-through: the curated fingerprint, as today |
| Is `observed_at` part of the identity? | **Yes**, as the resolved value. For a **derived** timestamp it is a pure function of the source, so the triple collapses to `(source_digest, release_id)` with no special case. For a **caller-supplied** one it is an assertion about *which* observation this is, so the same file with a different supplied timestamp correctly does not dedup |
| Same source after a converter upgrade? | **Dedups. No reconversion, no duplicate.** Deliberate reconversion is `force_reconvert=true`, which files a new document recording both `converter_version`s |
| Must a caller-supplied `observed_at` match for a retry to dedup? | Yes — a supplied timestamp is a caller assertion about the observation, so it joins the key when present |
| How does a client tell a retry from a genuine new scan? | `dedup_basis: source_digest \| content_fingerprint \| none` beside `created`. `created=false` + `source_digest` is "you sent this file before"; `created=true` is a new observation |

A genuinely new scan of the same image has different bytes (new `last_observed` at minimum), so it
is never suppressed — which is the failure mode this decision is shaped to avoid.

**The exact key, including `observed_at`.** The key is
`(source_digest, release_id, observed_at_resolved)`. Stating it with the resolved timestamp in it
removes the special case the first amendment left ambiguous:

- **Derived** `observed_at` is a pure function of the source bytes, so it is *constant* for a given
  source and the triple collapses to `(source_digest, release_id)` on its own. No special-casing.
- **Caller-supplied** `observed_at` is an assertion about *which observation* this is. The same file
  submitted with a different supplied timestamp is a claim about a **different** observation, so it
  must **not** dedup — and with the timestamp in the key, it doesn't.

**Enforced by the database, not by a lookup.** A `SELECT`-then-`INSERT` is a time-of-check /
time-of-use race: two concurrent submissions of the same source both miss, both convert, both
insert. So identity rests on **two UNIQUE constraints** and every write is
`INSERT … ON CONFLICT … DO NOTHING` with the conflict resolved by reading back the winner:

| constraint | protects |
| --- | --- |
| `UNIQUE (fingerprint)` — exists today, `store.go:73` | identical curated output. Because conversion is deterministic (D3), two concurrent submissions under the **same** converter version collide here even if the source-digest check is bypassed. This is the backstop |
| `UNIQUE (provenance_source_digest, subject_release_id, provenance_observed_at)` **partial**, `WHERE provenance_source_digest <> ''` — new | the same source across **different** converter versions, where outputs differ and the fingerprint would not collide. Partial so pass-through submissions (no source digest) are unaffected |

The pre-conversion lookup is therefore an **optimization and a cross-version identity**, never the
correctness mechanism: it saves converting a file we have already filed, and it is what makes a
converter upgrade dedup. Correctness under concurrency is the two constraints. A loser of either
race returns the winner's `evidence_id` with `created=false` — it does not retry and does not error.

**The conflict-resolution path, stated as SQL behaviour because the declaration does not establish
it.** Two traps, both verified against the current implementation:

1. **A second UNIQUE constraint is not covered by the existing `ON CONFLICT`.** `Save` today is
   `INSERT … ON CONFLICT (fingerprint) DO NOTHING RETURNING id`, and resolves the benign case by
   `errors.Is(err, pgx.ErrNoRows)` (`store.go:73–96`). A `23505` violation of the **source-digest**
   constraint is not `ErrNoRows` — it falls to `case err != nil` (`store.go:97`) and surfaces as
   `"evidence: insert: …"`, i.e. **a 500 where an idempotent `200` was required.** A single
   statement cannot name two conflict targets, so the write path must dispatch on the violated
   constraint **by name**:

   ```text
   INSERT … ON CONFLICT (fingerprint) DO NOTHING RETURNING id
     ├── RETURNING a row            → created = true
     ├── ErrNoRows                  → fingerprint dedup; same release ⇒ 200 created=false,
     │                                different release ⇒ ContentFiledElsewhereError (409)
     └── PgError 23505 with
         ConstraintName = evidence_source_digest_release_observed_key
                                    → SOURCE-digest dedup: read back that row's id and
                                      release, apply the SAME same-release / other-release
                                      rule, and return 200 created=false / 409
   ```

   An ordinary duplicate must never read as a persistence failure, and a cross-release duplicate
   must stay the loud `409` it is today — the distinction that was measured live on 2026-08-19,
   when returning another release's id read as success.

2. **`ON CONFLICT` inference does not match a partial index unless the predicate is restated.** If
   any statement ever targets the source-digest constraint directly it must be written
   `ON CONFLICT (provenance_source_digest, subject_release_id, provenance_observed_at)
   WHERE provenance_source_digest <> ''`; without the `WHERE` clause PostgreSQL cannot infer a
   partial index and the statement fails outright. The constraint is therefore created as a **named
   partial unique index** so the name is stable for the dispatch above, and the index name is part
   of the contract, not an implementation detail.

Both are proof obligations on the implementation, not claims about it — see `tasks.md` group 8.

*Rejected:* putting `converter_version` into the curated document (every upgrade then refiles the
whole estate); deduping on source digest alone, ignoring release (that is EDR-EVIDENCE-01 D3's 409
case and must stay a loud refusal, not a silent hit); relying on the lookup alone (the TOCTOU race
above, which under load files duplicate scans — the exact outcome D3 exists to prevent).

### D3a — `force_reconvert` creates a new generation; it never mutates or replaces

`force_reconvert=true` bypasses the source-digest lookup (not the constraints) and converts. What
happens next is determined, and reported, so a deliberate reconversion is never silently swallowed:

| outcome | response | what was filed |
| --- | --- | --- |
| the new converter produced **different** bytes | `201`, `created=true`, new `evidence_id`, `dedup_basis: none` | a **new, additional** evidence document. The prior one is **retained, unchanged** |
| the new converter produced **identical** bytes | `200`, `created=false`, the existing `evidence_id`, `dedup_basis: content_fingerprint`, `detail: "reconversion produced identical bytes; nothing filed"` | nothing — there was nothing new to file |

Three properties, stated because each is a way this could have gone wrong:

- **It never mutates.** Evidence is immutable (CON-0007) and there is no delete or retire in
  production (EDR-EVIDENCE-01 D8). A reconversion **adds**; the earlier document and its findings
  stay exactly where they are. The caller gets a second evidence id, not an edited first one.
- **It never silently dedups the deliberate act.** The identical-bytes case *is* a dedup, but it is
  reported as one, with `dedup_basis` naming *why* — so "I forced a reconversion and got the old id
  back" is an answer, not a mystery.
- **It is not a repair mechanism.** Two documents now describe the same scan under two converter
  versions, and **both** contribute occurrences downstream. KN-SCAN-4's shape is untouched: the
  corrected rows land *beside* the old ones. `force_reconvert` is for deliberately re-reading a
  source under a new converter, and the operator owns the consequence of two generations coexisting.

**What "both contribute occurrences" actually costs, measured in the schema rather than assumed.**
`faultline_matches` is keyed `PRIMARY KEY (release_id, faultline_id, component_purl)`
(`000001_knowledge.up.sql:53`) — **the evidence id is not in the key.** So:

| the converter change… | downstream effect |
| --- | --- |
| does **not** alter component identity | the second generation produces the **same** `(release, faultline, purl)` tuples, which collapse onto the existing rows. **Occurrence count does not change.** Re-processing is idempotent by construction |
| **does** alter component identity (purl or ecosystem derivation) | the second generation produces **different** `component_purl` values → **new rows**, while the old rows remain active. **Occurrence count rises**, and both identities are live on the same card and release |

The second row is the honest hazard, and it is the *usual* reason to bump a converter — the `.el8`
RPM inference and the purl-derived ecosystem are exactly the kind of rule a new version changes.
This is KN-SCAN-4(b)'s measured shape: on MRF 2026-09-17, 87 rows named one component under a raw
identifier while the canonical row already existed, in **87 of 87** cases.

Themis has a mechanism for it and it is **not automatic**: `faultline_matches.retired_at`
(`000010_match_retired.up.sql`) retires a superseded occurrence as a **projection change, never an
erasure** — the row stays so "we retired this" remains distinguishable from "this never happened".
Retirement is *asserted*, never inferred, so a reconversion does **not** retire anything on its own.

**Operational consequence, stated as guidance because the review is right to ask for it:**
`force_reconvert` is **not part of routine remediation**. It is occurrence-neutral only when the
converter change leaves identity derivation alone, and an operator cannot tell which case they are
in from the intake response. Until the downstream behaviour is measured on a real estate
(`tasks.md` 8.3), treat it as a deliberate, supervised operation whose occurrence delta is checked
afterwards — not a retry button. The intake response therefore echoes both `converter_version`s so
the delta is at least attributable.

*Rejected:* having `force_reconvert` supersede the prior document (there is no supersede in
Evidence, and inventing one here would put a mutable edge on an immutable store); having it delete
(no production delete, EDR-EVIDENCE-01 D8); having it return `409` on identical bytes (the request
succeeded and the system is in the asked-for state — that is a `200`, not a conflict).

### D4 — ONE converter per dialect, server-side, and the duplicates are retired

Today the Trivy translation exists in the browser (EDR-GUI-01 D16) and the Cortex translation exists
in Python under `scripts/`. Adding a third in Go would be the exact defect TESTING.md names: *"a
second converter is a defect, not a convenience"* — the 2026-09-10 case traced **579 permanently
unclearable occurrences** to an ad-hoc variant. Therefore:

- The Go converter registry in `internal/evidence/adapters/report` becomes **the** implementation.
- The browser's D16 translators are **replaced by a call to intake**. The GUI keeps its file-note
  UX (finding counts, skip counts) by reading them from the intake response.
- `scripts/cortex-csv-to-scan-report.sh` becomes a **thin wrapper that POSTs to intake**, keeping
  its name and CLI so documented procedures and muscle memory survive. Its Python judgement —
  ecosystem-from-purl, the `.el8` RPM-build inference behind KN-SCAN-3b, `origin_package_name` into
  `component.source` — is **ported with its tests**, not reimplemented from the prose.
- The port is a **behavioural equivalence task, not a rewrite**: the existing script's output on a
  committed fixture corpus is the oracle, and the Go converter must reproduce it byte-for-byte
  before the script is rewired. GUI-10 (translators have no unit-test harness) is closed by this.

**Byte-equality on a fixture corpus is necessary and not sufficient**, because these converters
carry *identity* judgement, not formatting: ecosystem from the purl, the `.el8` RPM-build inference
(KN-SCAN-3b), `origin_package_name` → `component.source`. Those decide how a component is
identified and therefore what it correlates to downstream — a converter that is byte-equal on twelve
fixtures can still diverge on the thirteenth input shape. So the acceptance gate is byte-equality
**plus named semantic invariants**, each its own test: component identity and purl behaviour,
ecosystem and source-field derivation, finding and skip counts, provenance and timestamp behaviour,
and the behaviour on missing / malformed / duplicate / ambiguous package observations.

**One invariant is load-bearing and stated separately: ambiguous identity must never be invented.**
EDR-IDENTITY-01 D6 resolves an observation with no usable purl onto the release's own component only
when **exactly one** matches by name+version, and otherwise **abstains** and reports it as
unresolved. The Go converter must preserve that abstention exactly — it must not turn an unresolved
observation into a plausible-looking package identity, because a plausible identity correlates and
an abstention does not. That is the 2026-09-10 false-positive class in one sentence.

*Rejected:* keeping three converters and documenting which to use (the documentation already said
that, and the operator still had no JSON road); shelling out to the Python script from Go (a service
that forks an interpreter per upload, with the script's path as deployment surface).

### D5 — Identification, validation and conversion are THREE stages, not one

**A recognised marker is not an admission decision.** The first draft conflated them, and the hole
is concrete: a Cortex array whose element 0 carries the right field set is *identified*, converted
with malformed later elements counted as skips, and the curated **output** then validates clean. The
bad input is admitted and the damage shows up as missing findings nobody asked about — the
silent-skip class, one ring further out than KN-SCAN-OBS-1.

So intake runs three distinct stages, each with its own refusal:

```text
identify  →  validate the INPUT against that dialect  →  convert  →  validate the OUTPUT  →  persist
   │                    │                                              │
unrecognised_format   source_invalid                              schema_invalid
```

**Stage 1 — identify (D5a).** `kind` and `format` may be declared; when absent they are detected
from the body. Detection is a closed, ordered table — first match wins, so precedence is
deterministic rather than dependent on map iteration:

| # | body | identified as |
| --- | --- | --- |
| 1 | `Content-Type: text/csv` + a recognised Cortex header row | `vuln-report` / `cortex-csv` |
| 1b | XML body whose root element is `<NessusClientData_v2>` (2026-10-24 amendment, N1) | `vuln-report` / `nessus` |
| 2 | JSON object with `bomFormat: "CycloneDX"` | `sbom` / `cyclonedx` |
| 3 | JSON object with `spdxVersion` | `sbom` / `spdx` |
| 4 | JSON object with `findings: [...]` | `vuln-report` / `curated` |
| 5 | JSON object with `Results: [...]` **and** `SchemaVersion` or `ArtifactName` | `vuln-report` / `trivy` |
| 5b | JSON object with `matches: [...]` **and** `descriptor.name` = `grype` (GUI-15, 2026-10-19) | `vuln-report` / `grype` |
| 6 | JSON array whose elements carry Cortex's required field set | `vuln-report` / `cortex-json` |
| 7 | anything else | **refused**, `unrecognised_format` |

**A declared `kind`/`format` that contradicts the body is refused** (`declared_format_mismatch`),
never silently overridden — the caller's assertion is information, and disagreeing with it quietly
is how a mis-declared document becomes a mystery later. Invalid *combinations* are refused the same
way: the matrix is `sbom × {cyclonedx, spdx, nessus}` (2026-10-26 P1) and `vuln-report × {curated, trivy, grype, nessus, nessus-csv,
cortex-json, cortex-csv}`, and nothing else. `kind=sbom, format=trivy` fails at identification.

Detected values are **echoed in the response** (`detected_kind`, `detected_format`) so the client
always sees what Themis decided.

**Stage 2 — validate the input (D5b).** The whole document, against the identified dialect, before
any conversion: SPDX/CycloneDX against their JSON schemas (required fields and structure, not just
the version marker); Cortex JSON against the required field set **for every element, not element
zero**; Cortex CSV header *and* every row; Trivy against its result shape. Failure is
`source_invalid`, with `detail` naming the element index or row number. **Identification tells us
which rules apply; this stage applies them.**

**Stage 3 — validate the output.** The curated document against the `scannerRecord` contract, or
the parsed SBOM against its inventory invariant. Failure is `schema_invalid`. This stage stays
because it catches converter faults, which stage 2 cannot.

A document rejected at any stage is **not filed** — see the ordering note in `design.md`: stages 1–3
are side-effect-free and only persistence writes.

**The accepted-input contract, matched to the maintained converter rather than invented.** "Reject
malformed records" and "skips are not fatal" (TESTING.md: one malformed finding must not void a
400-finding report) are both true, and they are about different faults. The line between them is
not a judgement call — it is read off `scripts/cortex-csv-to-scan-report.sh`, whose **only** skip
condition is line 77, `if not cve or not (purl or name)`. Everything else it coerces.

| input fault | D5b / converter behaviour | why |
| --- | --- | --- |
| body is not a JSON array / CSV has no header / unparseable quoting / invalid UTF-8 | **REJECT** (`malformed_body`) | we do not know what we are reading |
| an element is not an object, or a CSV row has a different column count | **REJECT** (`source_invalid`, naming the index/row) | the record's shape is unknown, so every field's meaning is a guess |
| duplicate or conflicting CSV headers | **REJECT** (`source_invalid`) | two `package_purl` columns make every row ambiguous; picking one invents data |
| `vulnerability_id` absent, **or** both `package_purl` and `origin_package_name` absent | **SKIP + count** | the maintained converter's one skip (line 77): structurally fine, semantically unusable — there is no flaw id or no component to attach it to |
| `cvss_score` unparseable | **coerce to 0**, never skip | the script's `num()` helper; a missing score is not a missing finding, and `severityFrom` falls back to the CVSS band |
| `cvss_severity == "Unknown"` | **coerce to ""**, never skip | the script's explicit rule; `value.ParseSeverity` then yields `SeverityUnknown` and the CVSS band decides |
| `fix_versions` absent or empty | **coerce to `[]`**, never skip | a finding with no published fix is still a finding |

So the tolerance is bounded by *structure*: a report is admitted with skips only when every record
was **well-formed**, and a record that is well-formed but unusable is counted, never hidden. A
structural fault anywhere refuses the whole submission — which is precisely what the first draft got
wrong. The Go converter must reproduce this table exactly; any divergence is a D4 equivalence
failure, not a new behaviour.

**Element 47 is a named regression fixture, not a general validation case.** `testdata/
cortex-json-malformed-at-47.json` is the 2026-10-05 export with element 47 structurally broken while
element 0 stays valid, committed with a provenance note. Its test asserts `source_invalid` naming
index 47 — and it exists because detection-passes-on-element-0 is the specific hole this amendment
closes. A general "invalid input is refused" test would pass without ever exercising it.

| body | detected as |
| --- | --- |
| object with `bomFormat: "CycloneDX"` | `sbom` / `cyclonedx` |
| object with `spdxVersion` | `sbom` / `spdx` |
| object with `findings: [...]` | `vuln-report` / `curated` |
| object with `Results: [...]` + `SchemaVersion`/`ArtifactName` | `vuln-report` / `trivy` |
| array whose first element has Cortex's field set | `vuln-report` / `cortex-json` |
| `text/csv` with a Cortex header row | `vuln-report` / `cortex-csv` |
| anything else | **refused**, `reason: unrecognised_format` |

The array-shaped Cortex export sits in that table on purpose: it is the exact body that caused the
incident, and a body Themis can name is a body Themis can convert.

### D6 — SBOM first, enforced with a named refusal and an explicit override

TESTING.md step 1 has said "SBOM first, report second" since September, with the reason:
correlation needs an inventory to record occurrences against, and the ownership bridge needs
siblings and edges to reach through. It was a procedure note, so it was skippable. Intake enforces
it: a vulnerability report for a release with **no SBOM-derived inventory** is refused with
`reason: no_inventory_for_release`, naming the release and what to upload first.

It is overridable with `allow_without_sbom: true`, because a standalone scanner report is a
supported case (KN-SCAN-1 folds at Asserted trust) and a hard block would break it. The override is
**recorded in provenance**, so a release whose findings rest on a report with no inventory behind it
says so. Default-refuse-with-override, not default-allow: the common case is the one the operator
got wrong.

**The operational definition, verified against the implementation rather than assumed.** "Has an
SBOM-derived inventory" means: *an Evidence document of `kind=sbom` exists whose
`subject_release_id` is this release*. That is sufficient, and the review's worry about weaker
intermediate states does not apply here, for two checkable reasons:

- **There is no "uploaded but not parsed" state.** `Register` parses inline (`register.go:115`) and
  `Save` writes the row and its `canonical_inventory` in **one transaction** (`store.go:70`). The
  inventory is visible the instant the SBOM upload returns `201`.
- **There is no "parsed but empty" state.** `NewEvidence` refuses it outright:
  `kind == KindSBOM && inventory.IsEmpty()` is a domain error (`evidence.go:100`). An SBOM that
  parsed to zero components cannot be filed at all.

So the five states the review distinguished — uploaded / registered / parsed / derived / available —
collapse to **two** for Evidence's own inventory: it exists with components, or it does not exist.
The check is release-scoped by construction (`subject_release_id`), so another release's inventory
can never satisfy it.

**And therefore no `inventory_not_ready` reason.** There is no window in which Evidence holds an
SBOM whose inventory is pending, so a distinct reason for it could never fire. A closed enum with a
dead value is worse than no value: consumers write handling for a state that does not exist and
trust a distinction the system cannot make. If a future change makes SBOM parsing asynchronous,
*that* change adds the reason — and the guard test in D11 forces it to.

**The real asynchrony is elsewhere, and D6 deliberately does not gate on it.** Knowledge's
*correlation* is async over the bus, so "the SBOM is filed" does not mean "Knowledge has correlated
it". D6's precondition is about the inventory existing as **evidence**, which is what a report needs
to be recorded against; whether Knowledge has caught up is a different question, answered by D10's
`next_checks`, not by refusing the upload.

*Note:* this is the one decision that changes the outcome of a request that succeeds today. A
scanner report uploaded before its SBOM currently succeeds and quietly under-matches.

### D7 — Product/Project/Release is resolved read-only; intake never creates identity

> **AMENDED 2026-10-12 — see the amendment "Bot-friendly intake" at the end of this document.**
> Intake may now **find-or-create the version** (the Release) under an existing Project when the
> caller passes `create_release=true` with the whole triple. It still **never** creates a Product or
> a Project, and the default — no `create_release` — is exactly the read-only behaviour described
> below. Everything in this decision stands except that one bounded widening.

Intake accepts **either** `release_id`, **or** the triple `{product, project, version}` which it
resolves **read-only** through the Registry seam. An unresolvable triple is refused with
`reason: unknown_release` and a body naming which of the three was not found.

Intake does **not** create Registry entities. Contexts collaborate only via events and **read-only**
HTTP reads; a write from Evidence into Registry is neither, and no convenience justifies punching
through that. Registering identity stays `POST registry/api/v1/{products,projects,releases}` — one
extra, idempotent call the first time a release exists, and zero calls on every scan after.

*Rejected:* a `create_if_missing` flag (a cross-context write, and it would let a typo in a product
name silently fork the estate graph — the thing Registry exists to prevent).

### D8 — Multiple reports per image are the normal case, and identity is content + release

Re-scanning the same image repeatedly is the expected workload, so the rules are stated rather than
left to emerge:

- **Byte-identical curated output, same release** → `200`, the existing evidence id, `created=false`.
  Nothing is filed twice.
- **Different content, same release** → a new evidence document. Both are retained; a release
  accumulates its scan history, which is what the posture's Scans card reads.
- **Byte-identical content, different release** → `409`, as today (EDR-EVIDENCE-01 D3). A new image
  version is a new Release.
- **A new image is a new Release**, not a new report on the old one. Intake cannot detect this and
  does not try; `provenance_image_digest` is accepted and recorded so the mismatch is at least
  *visible* later.

### D9 — The receipt: every intake is addressable, and slow work is resumable

Intake always returns a **receipt** — `intake_id`, `status`, and a `status_url` — and the client may
always come back to it. Two paths, one shape:

- **Fast path** (`201`/`200`): validation, conversion and registration completed inline. The receipt
  is already terminal and carries `evidence_id`.
- **Slow path** (`202 Accepted`): work exceeded `THEMIS_INTAKE_INLINE_BUDGET` (default `5s`) — a
  large CSV, a slow registry, a 50k-finding report. The receipt is returned immediately with
  `status: accepted`, and the work continues server-side.

`GET /api/v1/intake/{intake_id}` returns the receipt: `accepted → validating → converting →
registering → filed`, or `rejected` / `failed` with the reason and detail. Terminal receipts carry
`evidence_id`, `created`, and the conversion counts (`findings_total`, `findings_skipped`).

**The reason and its elaboration are two fields** (`reason` + `detail`), never concatenated. That is
not a style note: Governance flattened exactly this pair into `"<reason>: <detail>"`, which turned a
closed enum into free text and made every consumer's table lookup miss — a safety refusal rendered
as "no reason given" (fixed 2026-09-22). A consumer switches on `reason` and displays `detail`.

Receipts are retained `THEMIS_INTAKE_RECEIPT_TTL` (default 30 days) and are **not** evidence — they
are operational records of an attempt, including attempts that were refused. A rejected receipt is
the thing that was missing on 2026-10-05.

### D10 — Intake reports intake; correlation is answered by the context that owns it

The receipt is terminal at `filed`. It does **not** claim correlation is complete, because Evidence
cannot know that — Knowledge owns correlation, and asking Evidence to poll Knowledge would invent
the coupling the architecture spends a bus avoiding.

A terminal receipt therefore carries `next_checks`: the Knowledge and Governance URLs that answer
"did the work land" — `GET knowledge/api/v1/scanner-reports/{evidence_id}/unresolved` and
`GET governance/api/v1/releases/{release_id}/posture`. The client polls those for pipeline
completion.

**CORRECTED 2026-10-09, before any implementation.** The paragraph that stood here said there is no
single signal for "everything downstream of this upload is done", and filed a correlation-complete
event keyed to the evidence id as a follow-up. **That event already exists for SBOMs.** PR #129
(merged 2026-10-07, EDR-DELIVERY-01 N-M2a) added
`knowledge.release_correlation_completed.v1`: published once per correlation, carrying `sbom_id` —
the Evidence id of the SBOM — plus a closed `cause` of `new_sbom | rediscovery`, and appended to the
outbox **after** every other Knowledge event for that upload, so a consumer that handles it has
already handled every earlier fact. This EDR was drafted against `main` at `552c4e1`, two days
before that landed; the limit was true when written and false when merged.

**But it covers SBOMs only, and the asymmetry is the load-bearing part for this EDR.** Verified by
enumerating every caller: `AnnounceCorrelationCompleted` has exactly one non-test call site
(`app/correlate.go:314`, inside `CorrelationService.ApplyCorrelation`). The scanner-report path
(`ScannerReportService.ApplyIngest`, `app/scanner.go:274`) contains **no** announcement at all — it
reports counts through `s.report.ScannerIngest(...)`, a log seam, not the bus. The `vex` branch
publishes nothing either. `coordinator.go:44` is where the three kinds diverge.

So the state of the world is:

| upload kind | is there a "correlation finished" event? | what the receipt should do |
| --- | --- | --- |
| `sbom` | **yes** — `knowledge.release_correlation_completed.v1`, keyed by `sbom_id` | the receipt can reach a real `correlated` state, or at minimum name the event instead of sending the client to poll |
| `vuln-report` (any dialect) | **no** | `next_checks` polling stands, and is the only option |
| `vex` | **no** | out of scope here |

**What this changes in the design.** `next_checks` is no longer the answer for every kind — it is
the fallback for the kinds that have no event. An implementer reading the old text would have built
polling for the SBOM case that already has a push signal, and would have had no reason to notice
that the vulnerability-report case — the one this whole EDR exists for — is the uncovered one.

**What it does NOT change.** Evidence still does not poll Knowledge; the coupling argument stands.
Consuming that event is Governance's or a dedicated consumer's job, not Evidence's, so a receipt
that reports `correlated` for an SBOM needs a decision about **who** relays the event back to the
receipt. That is an EDR-DELIVERY-01 N-M2 question and is raised there, not settled here.

**Open question, for the owner of N-M2:** should `ScannerReportService.ApplyIngest` publish the same
event, with `cause` extended or a sibling event added? It would make the receipt's `correlated`
state uniform across kinds and remove the polling fallback entirely. It is not proposed here
because the event's own schema says it describes one SBOM, and widening a published
integration-contract v1 is a decision for its author.

### D11 — Validation is a closed taxonomy, refused at the border, before anything is filed

Every refusal names itself. `reason` is a closed enum on the Problem body; adding a value is a
contract change with a guard test, for the reason #116 cost us — a consumer that knows 6 of 15
reasons asserts "no reason given" for the other nine.

| reason | HTTP | means |
| --- | --- | --- |
| `unknown_release` | 404 | `release_id` or the `{product,project,version}` triple does not resolve |
| `no_inventory_for_release` | 409 | D6 — no SBOM-derived inventory, and no `allow_without_sbom` |
| `unrecognised_format` | 415 | D5a's table did not match; nothing was filed |
| `declared_format_mismatch` | 400 | D5a — a declared `kind`/`format` contradicts the body, or is an invalid combination |
| `malformed_body` | 400 | not well-formed JSON, unparseable CSV (RFC 4180), or invalid UTF-8 |
| `source_invalid` | 422 | D5b — recognised dialect, but the **input** failed its rules; `detail` names the element index or CSV row |
| `schema_invalid` | 422 | the **converted output** failed the `scannerRecord` / SBOM contract — **this is E1** |
| `empty_report` | 422 | zero findings, an empty array, or an SBOM with zero components |
| `observed_at_underivable` | 422 | D3 — no derivable timestamp and none supplied |
| `observed_at_invalid` | 422 | a timestamp was present but unparseable or implausible (pre-2000, or > 24h in the future) |
| `conversion_failed` | 422 | the dialect was valid but no finding survived translation |
| `checksum_mismatch` | 422 | `expected_checksum` does not match the submitted bytes |
| `duplicate_other_release` | 409 | D8 — byte-identical content already filed against a different release |
| `payload_too_large` | 413 | over `THEMIS_INTAKE_MAX_BYTES` (default 64 MiB) |
| `too_many_records` | 413 | over `THEMIS_INTAKE_MAX_RECORDS` (default 200 000 findings / CSV rows) |
| `unauthorized` | 401/403 | inbound-edge auth (EDR-SECURITY-01 F1) |

> **AMENDED 2026-10-12.** The enum grows by four — `create_release_conflict` (400),
> `incomplete_release_triple` (400), `ambiguous_name` (422) and `build_id_invalid` (400) — for the
> bot-intake amendment at the end of this document. The closed-enum discipline is unchanged: the
> OpenAPI enum, `TestIntakeReasonTaxonomyIsClosed` and every consumer rendering intake reasons grow
> in the same change.

`schema_invalid` is the decision that closes the incident: a curated report is validated against the
`scannerRecord` contract and an SBOM against its CycloneDX/SPDX schema **before** the aggregate is
built, so the body that halted a context for 31 hours is refused in milliseconds with a message
naming the field.

**And the same curated-shape check is added to `POST /evidence` for `kind=scanner-report`** — the
cheap half of E1 on the old door too. Intake is the good road, but the poison class must not remain
reachable through the door everything already uses.

### D12 — Idempotency is the client's to assert on the slow path

A retried `202` must not file twice. Intake honours `Idempotency-Key`; the same key within the
receipt TTL returns the **original receipt** rather than starting new work. Without a key, the
fast path is still safe (content addressing dedups), but a retry during slow-path processing may
register the same content twice — which content addressing then collapses to one document anyway,
leaving two receipts pointing at one evidence id. That is the documented behaviour, not a bug to
discover.

### D13 — The border has stated limits, and exceeding one is a named refusal

An unrecognised-format check does not protect a border; a border is protected by bounds. All are
configurable, all refuse before anything is read into the domain, and each maps to a reason in D11:

| bound | default | env |
| --- | --- | --- |
| request body | 64 MiB | `THEMIS_INTAKE_MAX_BYTES` |
| findings / CSV data rows | 200 000 | `THEMIS_INTAKE_MAX_RECORDS` |
| JSON nesting depth | 64 | `THEMIS_INTAKE_MAX_DEPTH` |
| CSV field length | 1 MiB | `THEMIS_INTAKE_MAX_FIELD` |

The size bound is checked **before** the body is buffered (`http.MaxBytesReader`), not after, or the
limit protects nothing it was meant to. Beyond size:

- **Invalid UTF-8** → `malformed_body`. Not repaired, not replacement-chaptered: a document whose
  bytes we silently altered is not the document whose digest we recorded.
- **Duplicate or inconsistent CSV headers** → `source_invalid`. Two columns named `package_purl`
  make every row's meaning ambiguous, and picking one is inventing data.
- **Empty document, empty array, zero data rows** → `empty_report`, never a filed document with
  nothing in it. (`kind=sbom` is additionally impossible to file empty — the domain invariant at
  `evidence.go:100`.)
- **Missing required fields, unparseable or implausible timestamps** → `source_invalid` /
  `observed_at_invalid`, with the element index or row number in `detail`.

**Nothing partial is ever persisted.** Stages 1–3 (D5) are pure; only persistence writes, and it
writes the aggregate and its outbox note in one transaction (`store.go:70`). A conversion that
fails at finding 180 000 of 200 000 leaves a `rejected` receipt and **no** evidence — there is no
state in which half a report is filed.

**And a validly-filed document whose downstream consumer later fails is not an upload failure.** The
receipt stays `filed`, truthfully, because it was. The consumer's failure is visible where it
happens — which is the stream-health gap filed separately as `OBS-HALT-1`, and is deliberately not
something this endpoint pretends to cover (D10).

## Honest limits

- **The filed document is not the operator's bytes** for any converted submission (D2). Provenance
  records the source digest and converter identity; it does not store the original. An estate that
  needs the vendor artifact retained verbatim needs a separate decision.
- **D6 changes an outcome that succeeds today.** A scanner report uploaded before its SBOM currently
  succeeds and under-matches silently; it will now be refused unless the caller opts in.
- **No completion signal for the whole pipeline** (D10). The receipt is terminal at `filed`.
- **KN-SCAN-4's shape is untouched.** An occurrence recorded with wrong attribution is not healed by
  re-uploading corrected data; the corrected rows land beside the old ones. Intake makes identities
  *stable* (one converter, D4) which is what keeps routine re-scans deduping — it does not
  retroactively repair anything.
- **The converter port is where the risk is.** D4's equivalence-against-fixtures gate exists because
  a subtly different Go converter would reproduce the 2026-09-10 false-positive class with better
  ergonomics.

## Realizes

CON-0001 (single ownership — Evidence owns its border), CON-0003 (explainable history — receipts
record refused attempts), CON-0007 (immutable evidence — D2 keeps the document JSON and unedited),
EDR-EVIDENCE-01 D2/D3/D5 (amended at D11), EDR-EVENTBUS-01 D8 (the poison class refused upstream of
the bus), EDR-IDENTITY-01 D6 (parser warnings surfaced in the receipt), EDR-SECURITY-01 F1/D10,
EDR-GUI-01 D16 (translators relocated, not duplicated), PARITY-GAP **E1** and **E11**, GUI-16 /
GUI-16b, GUI-10, KN-SCAN-1 / KN-SCAN-3b.

## Amendment log

**2026-10-09 — architecture review (D1–D6 reviewed; D7–D13 not yet seen by the reviewer).**
Direction retained, six contracts amended before implementation. What changed and why:

| # | change | driver |
| --- | --- | --- |
| **D3** | Idempotency identity for converted submissions moved to `(source_digest, release_id)` — **refined to the three-part key in the second pass below** — checked **before** conversion; all five identity questions answered in a table; `force_reconvert` added | A converter upgrade made the same source file a **new evidence document** — a duplicate scan, KN-SCAN-4's shape through a new door. Verified against `store.go:73` + `trust.go:51`. The first draft did not address it at all |
| **D5** | Split into three stages — identify / validate the **input** / validate the **output** — with `source_invalid` and `declared_format_mismatch` added, an ordered first-match detection table, and the `kind × format` matrix | A recognised marker is not an admission decision. A Cortex array valid at element 0 and malformed at element 47 was identified, converted with skips, and its *output* validated clean — the silent-skip class |
| **D2** | Provenance split into nine single-concept fields; "reconstructable" corrected to **verifiable-by-digest** | `converted_by = "cortex@1"` overloaded dialect, tool and version; and the draft's own honest-limits section contradicted its claim |
| **D4** | Acceptance gate is byte-equality **plus** named semantic invariants, including EDR-IDENTITY-01 D6's abstention rule stated explicitly | These converters carry identity judgement, not formatting. Byte-equal on twelve fixtures can still diverge on the thirteenth shape |
| **D6** | Operational definition of "has an inventory", **verified** rather than assumed; `inventory_not_ready` deliberately NOT added | The review's five intermediate states collapse to two: parsing is inline in one transaction (`register.go:115`, `store.go:70`) and an empty SBOM inventory is a domain error (`evidence.go:100`). A closed enum with a value that can never fire is worse than no value |
| **D13** | New — explicit border bounds (size, records, depth, field length), UTF-8 and CSV-header behaviour, and the no-partial-persistence guarantee | An unrecognised-format check does not protect a border; bounds do |

Three review points needed no change because D7–D13 already carried them, and are recorded here so
they are not re-raised: **upload success vs processing completion** is D9/D10 — the receipt is
terminal at `filed` and D10 states plainly that no endpoint claims pipeline completion;
**release identity and the REST contract** are D7 plus `design.md`'s wire contract; **no partial
evidence on failure** is D13 and `design.md`'s ordering note.

One review correction did not apply: `CycloneDX` is spelled correctly in all six occurrences here
and throughout the change.

**2026-10-09 (second pass) — three verification points raised before publication.**

| # | change | driver |
| --- | --- | --- |
| **D3** | Key stated exactly as `(source_digest, release_id, observed_at_resolved)`; identity moved onto **two UNIQUE constraints** with `INSERT … ON CONFLICT`, the lookup demoted to an optimization | A `SELECT`-then-`INSERT` is a TOCTOU race: two concurrent submissions of one source both miss, both convert, both insert. An index accelerates a query; it does not enforce an identity |
| **D3a** | New — `force_reconvert` creates a **new generation**, never mutates or replaces, and the identical-bytes case is reported with `dedup_basis` rather than silently swallowed | Evidence is immutable with no production delete or supersede (EDR-EVIDENCE-01 D8), so "replace" was never available; and a deliberate reconversion returning the old id must say why |
| **D5b** | Accepted-input contract written as a table **read off the maintained converter** (its only skip is line 77, `not cve or not (purl or name)`); element 47 named as a committed regression fixture | "Reject malformed records" and "skips are not fatal" are both true of different faults. The boundary had to match the converter's actual behaviour, not approximate it, or the Go port's equivalence gate would encode a different contract |

**2026-10-09 (third pass) — two proof obligations, and what verifying them found.**

| # | change | driver |
| --- | --- | --- |
| **D3** | Conflict-resolution path specified as SQL behaviour: dispatch on `PgError.ConstraintName`, plus the partial-index `ON CONFLICT` inference requirement and a **named** index as part of the contract | Verified gap, not hypothetical: `Save` resolves the benign case on `pgx.ErrNoRows` (`store.go:82`) and sends everything else to `case err != nil` (`store.go:97`). A `23505` on the new constraint would surface as `"evidence: insert: …"` — **a 500 where the contract requires `200 created=false`**. A single statement cannot name two conflict targets |
| **D3a** | Downstream occurrence cardinality stated as a two-case table, with the hazard named and `force_reconvert` placed **outside routine remediation** | `faultline_matches` is keyed `(release_id, faultline_id, component_purl)` with **no evidence id** (`000001_knowledge.up.sql:53`). So a reconversion is occurrence-neutral **iff** identity derivation is unchanged — and altering identity derivation is the usual reason to bump a converter, in which case occurrences rise and both identities stay live. KN-SCAN-4(b)'s shape: 87 of 87 rows, MRF 2026-09-17. `retired_at` exists but is *asserted, never inferred*, so nothing is superseded automatically |

Both are recorded as **open approval gates** (`tasks.md` group 8), not as satisfied claims. Neither
blocks M1, which does not ship `force_reconvert`.

**2026-10-09 (post-merge) — D10's honest limit was stale on the day it merged.**

| # | change | driver |
| --- | --- | --- |
| **D10** | The "no correlation-complete signal exists" limit is replaced by what actually exists, split by upload kind, plus an open question for N-M2's owner | PR #129 (2026-10-07) shipped `knowledge.release_correlation_completed.v1` keyed by `sbom_id` — exactly the event D10 filed as a follow-up. This EDR was drafted against `552c4e1`, two days earlier. Verified it is **SBOM-only**: one non-test caller (`correlate.go:314`), nothing in `scanner.go:274`. So the vulnerability-report case this EDR exists for is the one still uncovered, which the old text obscured |

Corrected before implementation started, so no code was written against the wrong assumption.

The reviewer's 20-check contract matrix is adopted as the implementation gate and mapped into
`openspec/changes/phase3-report-intake/tasks.md` group 6.

**2026-10-12 — Bot-friendly intake: a version may be created, and Registry identity becomes
idempotent.**

Driver: intake was built for a human with a runbook, and the next caller is a CI bot. A bot knows
`{product, project, version}` and its own build id; it retries on failure; and it has nowhere to put
the "register the release first" step. D7 as written forced that step out of band, and it is the one
part of the identity triple that is **new on every build** — the product and the project are owned by
a human and already exist, only the version is new. So a bot either carried a second credential and
a second service to call, or it hard-coded a release UUID a human had captured once, which is how a
pipeline ends up filing every build against one Release.

The owner's decisions below are **settled and recorded, not re-opened**. They are labelled `B1`–`B6`
(the amendment-local "decisions 1 to 6") so they can be cited without colliding with `D1`–`D13`.

### B1 (decision 1) — One request uploads ONE artifact

An intake request files **one** artifact: an SBOM **or** a scan report, never both. A bot sends the
SBOM and the scan report as **two separate requests**, each retried independently. There is no
multi-artifact transaction and no batch body.

This is a deliberate refusal of the obvious convenience, for two reasons already load-bearing
elsewhere in this EDR. First, identity: dedup (D3/D8) and the receipt (D9) are both *per
document*, so a two-artifact request would have two dedup outcomes, two reasons and two evidence ids
behind one `intake_id` — a receipt that cannot say what happened. Second, retries: the SBOM may
dedup while the report is refused `schema_invalid`, and a bot retrying "the upload" would have to
work out which half to resend. Two requests make each half idempotent on its own, which is what a
retrying caller needs.

**Ordering is unchanged and still matters:** D6's SBOM-before-report rule applies across the two
requests exactly as it applies across two script invocations today. The SBOM request is the one that
creates the version (B2); the report request then finds it.

### B2 (decision 2) — `create_release=true`, the triple only, and the exact order of operations

A new query parameter `create_release=true` is accepted **only together with the whole
`{product, project, version}` triple**. Intake **never** creates a Product or a Project. The order of
operations is fixed, and the order is the decision:

The **authoritative** sequence is B7 below (revised at the Gate A review); this list is its
identity part only. Intake authenticates; resolves the existing Product by name (read-only, never a
create); **authorizes the key against that Product before any further lookup** (B3); resolves the
existing Project under it (read-only); and, at B7's step 8 — after every border check — finds or
creates the version through **Registry's own code** (B4's idempotent upsert), then files the
artifact against the canonical release id.

`create_release=true` **together with `release_id` is `400`**: the caller named the release two ways
and intake will not guess which one it meant.

**Why this does not re-open D7's rejection of `create_if_missing`.** D7 refused that flag because "a
typo in a product name [would] silently fork the estate graph". That hazard is specific to the
**Product and Project** names, which are human-owned, long-lived, and the place a typo creates a
*parallel estate*. It does not transfer to the version in the same form, but it does not vanish either, and the
risk is stated rather than minimised (Gate A review, revision 2). **A typo in the version does not
create a parallel Product or Project, but it can create a separate Release and cause evidence to be
filed under the wrong version.** Example: the intended version is `R20.1`, the bot sends `R20.l`
(letter `l`); Themis creates `R20.l`, files the SBOM against it, and Knowledge raises findings under
that identity — the Release is not inert. The bounded-create decision **accepts that risk** because
the version is supplied by the CI pipeline, while the Product and Project identities remain
human-owned and must already exist: a typo in either of those is a **refusal** (steps 2–4), never a
creation. The pipeline must therefore supply a **validated** version identifier, and **Themis never
silently corrects or normalizes a version** (no case-folding, no trimming beyond what the URL
decoder does, no "did you mean"). This adds no version-format validation to this change's scope; it
makes the accepted risk explicit. The decision D7 rejected was "create whatever is missing"; this
one is "create the one thing that is new on every build, under identity a human already
established".

**Where the create happens in the step order, stated because "nothing is created on any refusal"
(B3) has to hold for the whole request, not just the authorization part.** Resolution stays where it
is today (step 3 of D5's order), so every existing refusal keeps its existing precedence — an
invalid-and-early report still reports `schema_invalid`, not something about release creation. The
**create** is deferred to immediately before the filing step, so a submission refused for
`schema_invalid`, `source_invalid`, `empty_report`, `no_inventory_for_release` or any other border
reason creates **nothing**. The honest exception is named rather than hidden: `duplicate_other_release`
is discovered by the database **at the insert**, so it is the one refusal that can follow a create.
The created version is retained (it is a legitimate Release that simply has no evidence yet), and a
corrected retry reuses it, because the create is idempotent.

**Consequence worth stating for the bot author:** a scan report sent with `create_release=true` for a
version that does not yet exist is refused `no_inventory_for_release` (D6) **before** the version is
created — correctly, because D6's point is that a report needs an inventory to be recorded against.
With B1's two requests this never bites: the SBOM request creates the version, the report request
finds it. A standalone report still works with `allow_without_sbom: true`, and then the version is
created.

**The architectural cost, named.** D7's note that "a write from Evidence into Registry is neither an
event nor a read" was correct and is not retracted — it is narrowed, with what replaces the wall
stated explicitly:

- the write is **one operation** that can create a version and nothing else; it is structurally
  incapable of creating a Product or a Project;
- it is **idempotent and enforced by Registry's own database constraints** (B4), so Registry — not
  Evidence — remains the authority on what "one Release" means;
- it is reachable **only through the `cmd/evidence` composition root's seam**, which already wires
  both rings for the read side (`registryReader`), carries primitives only, and gains exactly one
  method. An architecture test asserts the seam exposes no other write.

*Rejected:* having intake publish an event for Registry to act on (the release id is needed
synchronously, in this request, to file the document — an eventual create cannot answer it); having
the bot call Registry itself (that is the step a bot has nowhere to put, which is the whole driver);
`create_if_missing` for products and projects (D7's refusal, unchanged).

### B3 (decision 3) — Authorization must not leak existence

A `product:<id>` key naming **any** product other than its own gets the **same `403`** — whether
that product exists, does not exist, or is ambiguous. Only an **`admin`** key is told
`404 unknown_release` for a missing Product or Project. **Nothing is created on any refusal.**

This is the non-leak rule stated as a property rather than as a list of cases: for a product-scoped
key, every outcome of step 2 that is not "resolves to exactly my own product" is indistinguishable.
Otherwise intake becomes a product-name oracle for any holder of any product key — ask for
`{product: "acquisition-target", …}` and read the status code.

Three details follow from it, and each is a way the rule could be lost in implementation:

- **The authorization check is step 3, before the Project lookup.** Putting it after would leak
  project existence under a product the key may not see, by the same oracle.
- **Once a key is authorized for the Product, it gets the same answers an admin would** for the
  Project and the version — `404 unknown_release`, `422 ambiguous_name`, everything. There is
  nothing left to leak: the key already holds authority over that product.
- **`ambiguous_name` and `unknown_release` are admin-or-authorized answers only.** A product-scoped
  key that names someone else's product gets `403` even when the real answer is "that name matches
  two products".

**On an auth-disabled node** (`THEMIS_AUTH_DATABASE_DSN` unset) there is no principal, so intake
treats the caller as `admin` — the same posture every other route on that node already has, and the
reason `THEMIS_AUTH_REQUIRED=1` exists. `create_release` does not change the auth switch.

This also **closes part of EDR-SECURITY-01 D4's deferral** for the Evidence write surface, in the
same shape as EDR-DELIVERY-01 N-M0 closed it for Governance: a route that can resolve its resource
to a product authorizes `admin` or that product explicitly, fail-closed, instead of resting on the
method-based `AuthorizeWrite` floor. The existing `release_id` road keeps the floor it has today —
widening it is a separate decision and is **not** taken here.

### B4 (decision 4) — Registry uniqueness is enforced by the DATABASE, never by check-then-insert

| level | uniqueness |
| --- | --- |
| products | unique on `lower(name)` |
| projects | unique on `(product_id, lower(name))` |
| releases | unique on `(project_id, version)` — **exact**, not case-folded |

Registry's create-product, create-project and create-release become **idempotent find-or-create**:
`INSERT … ON CONFLICT` on those constraints, `200` when the row already existed and `201` when it was
created, so **two concurrent callers get one row**. This is the same reasoning D3 applied to Evidence
one paragraph at a time: a `SELECT`-then-`INSERT` is a time-of-check / time-of-use race, and an index
accelerates a query while a constraint enforces an identity. Two bots building the same version at
the same moment is the normal case, not the exotic one.

Case-folding is **deliberately asymmetric**. `Product` and `Project` names are human-typed labels, so
`"OAMP"` and `"oamp"` are one product and uniqueness folds case. A **version** is a machine-generated
build string where case can be meaningful (`R1917.256-RC1` vs `r1917.256-rc1` may genuinely differ in
a tagging scheme Themis does not own), so release uniqueness is exact. Folding versions would merge
two builds; not folding names would fork a product on a shift key.

**The stored casing is the FIRST caller's.** A later caller writing `"oamp"` against a stored
`"OAMP"` gets the existing row, with the existing casing, and no indication that its own spelling was
not used. That is the right trade — one product, one row — and it is recorded here because it is
otherwise a surprise.

**The migration refuses; it never repairs.** If any duplicate exists the migration **fails with a
clear message naming the duplicates**, and it **never merges or reassigns records**: merging two
products means re-pointing projects, releases, evidence, findings and positions, which is an estate
decision and not something a migration may take while an operator is watching a progress line. The
**2026-10-12 VM census found none**, including case-insensitive collisions, which is what makes
refuse-don't-repair a cheap guarantee rather than a blocked upgrade. The **down migration drops the
constraints only** and never touches data.

**The pre-flight cannot be raced (Gate A review, revision 2).** A duplicate inserted after the
pre-flight query but before `CREATE UNIQUE INDEX` would turn the named refusal into a bare `23505`
from the index build. So the migration runs as **one explicit transaction**. Its **first statement after `BEGIN`** is
`LOCK TABLE products, projects, releases IN SHARE ROW EXCLUSIVE MODE`. That mode blocks every
concurrent `INSERT`/`UPDATE`/`DELETE` on the three tables (it conflicts with `ROW EXCLUSIVE`) while
still allowing reads. Writes are therefore quiesced from the pre-flight through the last index, and
released at commit. (The mode also conflicts with itself, so two transactions that take it
serialize; but what stops two migration **runners** from both applying `000003` is golang-migrate's
own Postgres advisory lock and its `registry_schema_migrations` version row, not this table lock.) The indexes are built
**without** `CONCURRENTLY` (which cannot run inside a transaction); the lock is held for the
duration of the pre-flight and three index builds, **expected to be brief on the current registry
size** (it depends on table size, index-build time and database load), and a Registry write that
arrives meanwhile waits and then proceeds rather than failing.
The file says `BEGIN;` … `COMMIT;` explicitly, so the transaction boundary does not depend on how
the driver sends it. Under these conditions no maintenance window is required for this migration; the 2026-10-12 census is evidence the
refusal will not fire on the VM, not the mechanism that makes it safe.

**Name lookups abstain, and say *ambiguous*.** A lookup that matches more than one row **refuses**,
with a message that says the name is ambiguous — **not** that it is not registered. Today the seam
returns an empty id for both `0` and `>1` matches, and the resolver reports both as
`unknown_release`: "no product named X is registered" is a false statement about a product that is
registered twice, and it sends the operator hunting for a typo that is not there.
**`ReleaseIDByVersion` must abstain too**, instead of returning the first match — it currently scans
a project's releases and takes the first exact hit, which silently picks a winner the moment two
exist. Both abstentions survive the constraints above (which make `>1` unreachable) on purpose: an
un-migrated estate still has the old shape, and a guard that only holds because of an index is a
guard that disappears with the index.

### B5 (decision 5) — `build_id`: optional, provenance, echoed, and deliberately inert

A new optional query parameter `build_id`, **at most 256 characters**, stored as artifact provenance
on the evidence record — a **new provenance column** beside `provenance_source` and
`provenance_image_digest` — and **echoed on the receipt**.

It is **not unique, and it is not used for dedup, correlation or current-SBOM selection.** It is a
label that answers "which pipeline run produced this document", and nothing reads it to make a
decision. That inertness is the decision, not an omission: a build id that influenced dedup would
make two genuinely identical documents from two builds into two evidence rows, and a build id that
influenced correlation would be a second identity for a component Themis already identifies by purl.

**The dedup interaction, stated because it is the one place `build_id` can look broken.** A
byte-identical retry **dedups to the existing artifact and keeps the FIRST upload's `build_id`**; the
retry's value appears **only on its own receipt**. So the receipt's `build_id` and the filed
document's `build_id` can differ, by design: a receipt records an **attempt**, and the evidence row
records what was **filed**. Evidence is immutable (CON-0007) — a second upload cannot rewrite the
first one's provenance, and an `ON CONFLICT … DO NOTHING` write does not try to.

**The bound is 256 Unicode code points, not bytes** — the unit OpenAPI's / JSON Schema's
`maxLength` counts, so the spec and the code cannot disagree. The Go check is
`utf8.RuneCountInString(v) <= 256` on the percent-decoded value, never `len(v)`: 256 × `é` is 512
bytes and is **accepted**; 257 code points of anything is refused. A value that is **not valid
UTF-8** after decoding is refused by the same reason, because a code-point count of malformed bytes
is not a defined quantity.

**Over the bound or malformed is a named refusal, not a truncation.** The same reasoning D13 applies
to invalid UTF-8: a value we silently altered is not the value the caller recorded, and a provenance
field is exactly where a silent rewrite is most expensive to discover. Bounds at this border refuse
by name (`build_id_invalid`, `400`, the detail saying which: too long or not UTF-8).

### B6 (decision 6) — What does NOT change

- **Same-bytes dedup** is unchanged (D3, D8): same curated bytes, same release → `200`,
  `created=false`, the existing `evidence_id`.
- **A different SBOM or scan report for the same release is filed as NEW HISTORY**, not as a
  replacement (D8). This is not a convenience: **EDR-DELIVERY-01 M2-5 relies on successive SBOMs per
  release** — its baseline is "the immediately-previous SBOM of the SAME Release, by upload order" —
  so a release that accumulated its SBOMs is the precondition for the rebuild loop being able to say
  whether a rebuild closed anything.
- **`409 duplicate_other_release`** across releases is unchanged (D8, EDR-EVIDENCE-01 D3). Byte-
  identical content on a different release stays a loud refusal.
- **D6's SBOM-before-report rule** is unchanged, including the `allow_without_sbom` override.
- **No multi-artifact transaction** (B1), and **receipts remain the intake-only checkpoint** — a
  receipt is terminal at `filed` and claims nothing about pipeline completion beyond D10's
  `next_checks`.

### Status codes — `create_release` and authorization

The rows are the whole contract; a row that is absent is a case the implementation must not invent.
`unauthorized`, `unknown_release` and `duplicate_other_release` are existing D11 reasons;
`create_release_conflict`, `incomplete_release_triple`, `ambiguous_name` and `build_id_invalid` are
**new values in D11's closed enum**, and adding them is a contract change that grows the OpenAPI
enum, the guard test and every consumer rendering intake reasons **in the same change** (the #116
cost, D11).

| # | request | key scope | response | created? |
| --- | --- | --- | --- | --- |
| 1 | any | missing / invalid / expired / revoked key | `401` `unauthorized` | nothing |
| 2 | any | `read` or `delivery:callback` | `403` `unauthorized` (write floor, EDR-SECURITY-01 D4) | nothing |
| 3 | `release_id`, no `create_release` | authorized | **unchanged**: `201` filed · `200` `created=false` same-release dedup · `409` `duplicate_other_release` · `404` `unknown_release` | no Registry write |
| 4 | triple, no `create_release` | authorized | **unchanged** D7 behaviour: resolved read-only, `404` `unknown_release` naming the part that missed | no Registry write |
| 5 | `create_release=true` **and** `release_id` | any | `400` `create_release_conflict` | nothing |
| 6 | `create_release=true`, triple incomplete | any | `400` `incomplete_release_triple` | nothing |
| 7 | `create_release=true` + triple | `product:<P>`, product name resolves to **P** | continue to the Project lookup (rows 11–14) | — |
| 8 | `create_release=true` + triple | `product:<P>`, product name resolves to **another** product | `403` `unauthorized` | nothing |
| 9 | `create_release=true` + triple | `product:<P>`, product name resolves to **nothing** | `403` `unauthorized` — **byte-identical to row 8** | nothing |
| 10 | `create_release=true` + triple | `product:<P>`, product name **ambiguous** | `403` `unauthorized` — **byte-identical to rows 8 and 9** | nothing |
| 11 | `create_release=true` + triple | `admin`, product missing | `404` `unknown_release`, naming the **product** | nothing |
| 12 | `create_release=true` + triple, product resolves | `admin` or row 7 | project missing → `404` `unknown_release`, naming the **project** | nothing |
| 13 | `create_release=true` + triple, product resolves | `admin` or row 7 | product or project name matches **>1** row → `422` `ambiguous_name`, wording states **ambiguous**, never not-registered | nothing |
| 14 | `create_release=true` + triple, product and project resolve | `admin` or row 7 | version find-or-create, then the normal filing outcomes: `201` filed · `200` `created=false` · `409` `duplicate_other_release` · any D11 border refusal | the version is created only immediately before filing — see B2. `409` is the one refusal that can follow a create |
| 15 | `build_id` over 256 Unicode code points, or not valid UTF-8 | any | `400` `build_id_invalid` | nothing |
| 16 | `release_id` (any `create_release` value but `true`) | `product:<P>`, release belongs to **P** | the normal filing outcomes, as row 3 | no Registry write |
| 17 | `release_id` | `product:<P>`, release belongs to **another** product | `403` `unauthorized` | nothing |
| 18 | `release_id` | `product:<P>`, release **does not exist** | `403` `unauthorized` — **byte-identical to row 17** | nothing |
| 19 | `release_id` | `admin`, release does not exist | `404` `unknown_release` (unchanged) | nothing |

Note on rows 5 and 6 versus row 4: an **incomplete triple without** `create_release` keeps today's
`404 unknown_release`, because resolution is a lookup and "not found" is the honest answer. With
`create_release=true` the caller has asked intake to **create**, and a partial name is not something
that can be created from — so it is a malformed request, `400`. The distinction is deliberate and no
existing response changes.

### B7 — Revision 1 (Gate A review, 2026-10-12): authorization on BOTH paths, and the one authoritative order

The first draft authorized a `product:<id>` key only on the **name** path. The `release_id` path
rested on the method-based write floor (`AuthorizeWrite`), which sees a principal and no resource —
so a `product:<A>` key could file evidence against **product B's release** just by naming its id.
That is a gap **today**, not one this change introduces, but `create_release` makes product-scoped
CI keys the normal caller, so it is closed here, on both doors.

**Both paths authorize the resolved Product, read-only, before anything is written.**

- **Name path:** resolve the Product by name → `AuthorizeProduct` → resolve the Project → look up
  the version (read-only; "absent" is a valid answer when `create_release=true`).
- **`release_id` path:** load the Release → its Project → its owning Product → `AuthorizeProduct`.
  For a `product:<P>` key, a release of another product **and a release that does not exist** get
  the same `403` (rows 17–18): the non-disclosure rule of B3 applies to ids exactly as to names.
  An `admin` key keeps today's `404 unknown_release`.
- **`POST /evidence` (the old door)** gets the same `release_id`-path check, so the old door is not
  a way around the new one. That route already rejects unknown releases through `SubjectRef`; it
  gains only the ownership check.
- **The one existing response that changes:** a `product:<P>` key naming a non-existent
  `release_id` used to get `404`; it now gets `403`. Admin and auth-disabled callers see no change.

**The authoritative order.** This is the sequence the implementation and its tests conform to; the
design document's §3 restates it, and where any text in this amendment reads differently, this list
wins. It keeps the **implemented** D5 order (size → identify → resolve → convert → validate output →
SBOM-first → file) and inserts the new steps into it; no existing reason moves relative to another.

| # | step | refusals it can produce | writes? |
| --- | --- | --- | --- |
| 0 | **Authenticate** + the method write floor (EDR-SECURITY-01) | `401` / `403` `unauthorized` | no |
| 1 | **Parameter validation**, side-effect-free, needs no body | `create_release_conflict`, `incomplete_release_triple`, `build_id_invalid` | no |
| 2 | Size bound (D13) | `payload_too_large` | no |
| 3 | Identify the body (D5a) | `unrecognised_format`, `declared_format_mismatch` | no |
| 4 | **Resolve + authorize**, read-only, both paths as above | `403` `unauthorized` (non-disclosing), `404` `unknown_release`, `422` `ambiguous_name` | no |
| 5 | Validate the input + convert (D5b, D3) | `malformed_body`, `source_invalid`, `observed_at_*`, `conversion_failed`, `too_many_records` | no |
| 6 | Validate the output (D11, the E1 half) | `schema_invalid`, `empty_report` | no |
| 7 | SBOM-before-report (D6). A version still to be created has no inventory. | `no_inventory_for_release` | no |
| 8 | **Find-or-create the version** — only with `create_release=true` and only if step 4 found it absent | (a store failure → `failed`) | **Registry** |
| 9 | File + receipt (D3, D8, D9) | `200` `created=false`, `409` `duplicate_other_release` | **Evidence** |

Two consequences, stated so a test can hold them. **Step 1 before step 2** means a request that is
both oversized and carries a malformed `build_id` reports `build_id_invalid`; that can only happen
on requests using the new parameters, so no existing request's answer changes. **Step 3 before
step 4** means a product-scoped key sending an unidentifiable body about someone else's product gets
`415`, not `403`; that answer depends only on the body, so it discloses nothing about which
products exist.

### What this amendment does NOT touch

- **EDR-DELIVERY-01 M2-5 is untouched.** The baseline stays the immediately-previous SBOM of the same
  Release by upload order, and the targeted set still does not grow mid-cycle. B6 is what M2-5 rests
  on, and this amendment strengthens it (more releases now accumulate their own SBOMs instead of a
  pipeline filing every build against one hard-coded Release) without changing a word of it. The
  `ci_rebuild` callback path is unchanged: nothing here adds, removes or re-times a delivery kind.
- **Current-SBOM ("effective inventory") selection and finding reconciliation** are **out of scope**
  and gated behind their own design — filed as **"Current SBOM and finding cleanup"** in
  `docs/BACKLOG.md`. B6 keeps every SBOM as history, which is correct and is also why a release whose
  components changed can still carry open Findings for components the newest inventory no longer
  lists. That is a known, filed gap, not something this amendment may fix in passing.
- **`build_id` correlation** — nothing reads it (B5).
- **Receipt retention** — `THEMIS_INTAKE_RECEIPT_TTL` is unchanged at 30 days. A bot that needs a
  longer audit trail than that is asking for a different record, not a longer-lived receipt.

Implementation loci, so the next reader does not have to re-find them: `internal/registry`
(store migrations + the app service's three create use cases), `cmd/evidence/main.go`'s
`registryReader` (the seam, which gains one write and the ambiguity sentinel),
`internal/evidence/adapters/subjectref/resolver.go` (the resolve/authorize/create order), and
`internal/evidence/domain/evidence.go`'s `Provenance` (the new `build_id` field) plus the intake
receipt. The change is scaffolded as `openspec/changes/phase3-bot-intake`. **Scope is the `themis`
repository only; `themis-ai-runtime` needs no change.**

**2026-10-24 — Nessus (`.nessus` XML) becomes a vuln-report dialect.**

Driver: the owner's scan team produces Nessus reports, and there was no road for them. Intake reads
JSON and Cortex CSV only, so a `.nessus` file is refused `unrecognised_format`, and the HTML report
Nessus also produces is a page for people, with no schema. Two real samples were read before this
was written (one HTML report, one `.nessus` export of a different scan; neither is committed — both
carry host addresses and site names). DefectDojo's Tenable parser was read too: it takes only
`.nessus`/`.csv`, keeps one finding per plugin, keeps only the **first** `<cve>` of a plugin, and
never reads the package lines. Themis needs the opposite on the last two points, because a Themis
finding is CVE × component.

**What the `.nessus` sample measured** (credentialed, RHEL 8, four hosts of one build; numbers are
host 1, the other three within a few results):

| result class | how it is recognised | results | distinct CVEs |
| --- | --- | --- | --- |
| **A. vendor advisory check** | `pluginFamily` ends in `Local Security Checks`, `plugin_output` carries `Remote package installed : <nvr>` / `Should be : <nvr>` | 3 | 4 |
| **B. upstream version check on a package-manager file** | `Installed version` / `Reported version` + a path or banner, usually `Potential Vulnerability : Managed` | ~104 | most of 250 |
| **C. upstream version check on software no package manager owns** | same shape, path outside the RPM database (a hand-installed Tomcat, vendored gems) | a handful | few |
| no CVE (ports, ciphers, users, inventory) | no `<cve>` element | ~150 | 0 |

Class B is the trap. Nessus compares `openssl 1.1.1k` with upstream OpenSSL and reports every CVE
fixed after it — but RHEL backports the fixes and keeps the version string, and Nessus itself says
"has not tested for this issue but has instead relied only on the self-reported version number".
Filed as findings, ~250 mostly-false CVEs would open per release, on components Themis already
judges correctly from the SBOM and the vendor feed, and the version-range rule could never clear
them (an upstream range does not speak for an RPM — EDR-KNOWLEDGE-01 D13). It is KN-GO-1's shape
through a new door.

The owner's decisions (2026-10-24) are recorded as **N1–N10**.

### N1 — `vuln-report × nessus` joins the matrix; detection is by root element

The matrix becomes `vuln-report × {curated, trivy, grype, cortex-json, cortex-csv, nessus}`. D5a
gains one row, **1b**: after the CSV row (a body declared `text/csv` is still never tried as
anything else) and before the JSON rows, because the body does not open as JSON:

| # | body | identified as |
| --- | --- | --- |
| 1b | body whose first element (after an optional XML declaration, BOM, comments and whitespace) is `<NessusClientData_v2>` | `vuln-report` / `nessus` |

Content-Type is informational for XML (`application/xml`, `text/xml` and
`application/octet-stream` are all accepted); the root element decides. Any other XML root, or a
`NessusClientData` (v1) root, is `unrecognised_format` naming the root it found.

The XML reader is the standard library's `encoding/xml`, which does not resolve external entities
or fetch DTDs, so a hostile `.nessus` cannot reach the network or the filesystem. A `<!DOCTYPE>`
carrying an internal entity declaration is refused `malformed_body` rather than expanded.

### N2 — One file, many hosts, one release

A `.nessus` file names one or more `ReportHost`s. **All of them are filed under the one release the
request names** — the owner's case is several hosts running one build. Uploading a multi-host file
to a release is the caller's assertion that every host in it runs that release; Themis cannot check
it and does not try. No `host=` filter in v1: a scan of mixed builds is split in Nessus before
export.

### N3 — Only class A is converted; everything else is counted

| source | converter behaviour |
| --- | --- |
| ReportItem with no `<cve>` | not a finding; **not counted** (it is not a vulnerability record) |
| class A item, per `<cve>` × per `Remote package installed` line | **one curated finding** |
| class A item whose package lines do not parse (N4) | **SKIP + count**, per `<cve>` |
| class B or C item, per `<cve>` | **SKIP + count** |

So `findings_total` = every (host, plugin, CVE[, package]) unit considered and `findings_skipped`
the class B/C and unparseable units, and the curated document carries exactly the difference (the
`Stats` invariant). On the sample: ~800 considered across four hosts, almost all skipped — and the
receipt says so, which is the point (KN-SCAN-OBS-1). Identical findings from several hosts are
**not** de-duplicated in the converter: they collapse at the match key
`(release_id, faultline_id, component_purl)` downstream, and keeping them keeps the count honest.

Class B/C are not thrown away for ever; they are out of v1 (see the gates below).

### N4 — The component is name + version + `rpm`, never a purl

`Remote package installed : <nvr>` is split by the RPM rule — the last two `-` separate version and
release, the rest is the name — into `component.name` and `component.version` (`<version>-<release>`,
with an `E:` epoch kept as written when Nessus prints one). `component.ecosystem` is `rpm`.
**No purl is built.** The finding's identity is resolved onto its SBOM twin by the existing
purl-less path (EDR-IDENTITY-01 D2, `ResolveIdentity`, exact name + version), and an observation
with no twin is reported as unresolved by the existing unresolved query — never guessed. D6
(SBOM first) is what gives it twins to resolve onto.

### N5 — `Should be` is the fixed version, kept unattributed

The `Should be : <nvr>` version goes into the finding's `fixed` list. Like every scanner's fix it
stays unattributed for per-component verdicts (KN-FIX-1); the vendor feed remains the authority on
whether a build is fixed.

### N6 — `observed_at` is the host's own end time

Each finding's `observed_at` is its host's `HOST_END_TIMESTAMP` (unix seconds) as RFC 3339, falling
back to parsing `HOST_END` (`Tue Aug 11 19:35:12 2026`). The document's derived timestamp is the
latest host's. No host time and none supplied is `observed_at_underivable` (D3) — never `now`.

### N7 — Severity, scores and names

`scanner` = `nessus`; `converted_by` = `nessus@1`. `cvss_score` / `cvss_vector` from
`cvss3_base_score` / `cvss3_vector`; `severity` from `risk_factor` (`None` → empty, so the CVSS band
decides). `cisa-known-exploited`, `epss_score` and `vpr_score` are **not** carried: the curated
contract has no field for them and Knowledge has its own EPSS/KEV feeds. Adding them is a curated
contract change, not this amendment.

### N8 — The converter emits nothing about the host

The curated document carries CVE, component, versions, scores, scanner name and time. **No IP,
hostname, FQDN, MAC, BIOS UUID, user name or `plugin_output` text** reaches it. The raw body is never
stored (D2: only its digest is), so a host's identity never becomes evidence. Test fixtures are
synthesized or scrubbed; no real export is committed.

### N9 — GUI and REST

Same endpoint, `POST /api/v1/intake`, `Content-Type: application/xml`. The dashboard's upload
picker accepts `.nessus` and `.xml` and sends them as `application/xml`. No Jenkins road in v1: the
owner uploads by GUI or REST, naming the release by its triple as today.

### N10 — Bounds

D13's body bound applies unchanged: 64 MiB (`THEMIS_INTAKE_MAX_BYTES`) fits about thirty hosts of
the sample's size. D13's record, depth and field bounds are not wired for any dialect yet, and this
amendment does not wire them for one; `encoding/xml` carries its own nesting limit, which is enough
for a document the reader never recurses on.

### Open gates (not decided here)

| # | gate | why it is open |
| --- | --- | --- |
| G1 | **Version spelling.** Measure on the VM whether Nessus `<version>-<release>` equals the SBOM inventory's `version` for the same RPMs (epoch is the risk). If not, N4 needs a stated normalisation, decided then, not guessed now | `ResolveIdentity` is exact-match; a systematic spelling difference turns every class A finding into an unresolved one |
| G2 | **Class B as information.** Whether "Nessus saw `openssl 1.1.1k` and believes these CVEs apply" should be shown anywhere at all, below the finding line | it is mostly noise on RHEL, but it is the scanner's honest claim |
| G3 | **Class C (v2).** Hand-installed software is a real blind spot of an RPM SBOM. It needs a plugin → package-identity rule that never guesses | worth doing; not safe to rush |
| G4 | **A fix is an absence.** Next week's scan simply omits a fixed issue, and nothing closes a scanner Finding on absence | same design as "Current SBOM and finding cleanup" (`docs/BACKLOG.md`) |

### What this amendment does NOT touch

- No new evidence kind: a Nessus report is filed as the curated `scanner-report` document, so
  Knowledge, Governance and the receipt shape are unchanged.
- No new receipt fields. A host count in the receipt would be useful and is a separate, small ask.
- D6 (SBOM first), D7/B2 (release resolution and `create_release`), D3 (idempotency on the source
  digest) apply to `.nessus` exactly as to every other dialect.

**2026-10-26 — A `.nessus` export is the release's SBOM; a Nessus CSV is its scan report.**

Driver: the owner's teams work with **two** exports of each Nessus scan, and give them two roles:
the `.nessus` file is their SBOM (it lists the installed packages) and the CSV is their scan report
(one row per finding). Themis takes them in those roles. The 2026-10-24 amendment had read the
`.nessus` file for its **findings**; the first real pair showed how little that gives on a patched
host — a fully patched RHEL 8.10 host produced **0 findings of 456 considered**, correctly, because
every CVE in it was an upstream version guess. What the `.nessus` file does carry is the host's
full package list: plugin **22869** ("Software Enumeration (SSH)") prints every installed RPM as
`name-version-release|epoch installdate|vendor|packager` — **1291 packages, 1249 of them from the
OS vendor** — with the OS stated in `HostProperties` (`operating-system`, `cpe-0`). Filed as an
inventory, Themis's own correlation (OSV + the Red Hat feed, which judge backports correctly)
finds the real CVEs, exactly as for any SBOM. The CSV of the same scan was checked against the
`.nessus`: same host, same 245 plugins, same 300 CVEs, one row per (plugin, host, port, CVE).

The decisions are **P1–P9** (the `.nessus` inventory) and **C1–C6** (the CSV report).

### P1 — A `.nessus` upload is an SBOM by default

`POST /api/v1/intake` with a `.nessus` body files its package list as an SBOM: the receipt says
`detected_kind: sbom`, `detected_format: nessus`. The matrix becomes `sbom × {cyclonedx, spdx,
nessus}`. The 2026-10-24 report road stays, but only when asked for: `kind=vuln-report` on a
`.nessus` body converts its findings as N1–N10 describe. This is the first use of D5's declared
`kind`; a declared kind that the body cannot be is `declared_format_mismatch` (the reason already
exists). One request still files ONE artifact (B1).

### P2 — What is filed is a CycloneDX document, built server-side

D2/D5 say an SBOM is identified, never converted. This is the one exception, and it is bounded:
the converter `nessus-inventory@1` turns plugin 22869 into a **CycloneDX 1.5 JSON** document, and
that document is filed as `kind=sbom`, `format=cyclonedx`, with `converted_by` and `source_digest`
recorded exactly as for a converted report. Evidence's existing CycloneDX parser reads it, so
there is still exactly **one** SBOM reader and the inventory invariant (non-empty) applies
unchanged. The filed document is a real standards SBOM: it exports and re-imports like any other.

It is deterministic in the source bytes (D3): components sorted by purl, no generated serial
number, `metadata.timestamp` = the latest host's end time (2026-10-24 N6), never the clock. A
re-upload of the same `.nessus` produces the same bytes and dedups.

### P3 — Identity comes from the scan, and only where the scan states it

A package line becomes a component **with a purl** only when all of these hold:

1. the host's OS is one Themis maps (`Red Hat Enterprise Linux` → `redhat` / `rhel`, `Rocky
   Linux` → `rocky`, `AlmaLinux` → `almalinux`), with its version read from `operating-system`
   (`… release 8.10` → `distro=rhel-8.10`);
2. the line's **vendor is that OS's own vendor** (`Red Hat, Inc.` on RHEL);
3. the name-version-release splits by the RPM rule (2026-10-24 N4).

The purl is `pkg:rpm/<namespace>/<name>@<version>-<release>?distro=<os>-<x.y>`, plus `&epoch=N`
when the line carries a numeric epoch. The version field carries **no** epoch, which is the form
the Nessus advisory lines used in every sample seen, so a report from the same scan resolves onto
these components by exact name + version (2026-10-24 gate G1, for this road). This is not an
invented identity: the namespace, distro and version are each read from the scan, the way an SBOM
generator reads them from the RPM database.

Every other line — another vendor (EPEL, a database vendor's repo, in-house builds), an OS Themis
does not map, a line that does not split — is **counted and not filed** (no purl, no component).
Abstaining keeps EDR-IDENTITY-01 D3: a purl namespace is an ecosystem claim, and a guessed one
would correlate the wrong advisories.

### P4 — The receipt counts what was left out

The receipt's `components` is the kept count. A new field `components_skipped` carries the
abstentions, so "1249 of 1249" and "1249 of 1291" do not look alike (KN-SCAN-OBS-1's rule, applied
to an inventory). It is 0 for every other SBOM, which converts nothing.

### P5 — No source package, and what that costs

Plugin 22869 does not print the source RPM, so `Component.Source` stays empty. Knowledge already
falls back to the binary name (`componentPackage`) for range and statement lookups. That is right
for most packages and loses matches where the distro feed keys only on the source name (the
`openssl-libs` ← `openssl` shape). Measured, not guessed: gate **P-G1** below.

### P6 — Many hosts, one inventory

All hosts' lists are merged into one document; identical purls collapse. Two hosts reporting two
versions of one package keep **both** components — they are the same release by the caller's
assertion (2026-10-24 N2), so a difference is real drift and must stay visible. No host name,
address or MAC is written (2026-10-24 N8).

### P7 — A release with a real SBOM too

If a release already has a CycloneDX/SPDX SBOM, a Nessus inventory is filed beside it as a second
SBOM, like any other second SBOM (B6). Which inventory is "current" is EV-CURRENT-SBOM-1's design,
not this amendment's.

### P8 — The plugin must be there

A `.nessus` with no plugin 22869 output (uncredentialed scan, plugin disabled), or with no host
whose OS is mapped, is refused `source_invalid` with the detail naming which, rather than filed as
an empty SBOM (which the domain forbids anyway).

### P9 — GUI and REST

REST: the same endpoint and `Content-Type: application/xml`. Dashboard: a `.nessus` file is sent
as before and now files as the SBOM.

### C1 — A Nessus CSV is identified by its header row

D5a row 1 (CSV) recognises a second header set beside Cortex's. A CSV whose header row carries
`Plugin ID`, `CVE`, `Host`, `Name` and `Plugin Output` is `vuln-report / nessus-csv`. A header
carrying both sets is refused `unrecognised_format` rather than guessed at. The matrix gains
`vuln-report × nessus-csv`.

### C2 — Same rules as the `.nessus` report road

The converter `nessus-csv@1` applies N3–N5 row by row: a row whose `CVE` is empty is not a finding
and not counted; a row whose `Plugin Output` carries `Remote package installed : <nvr>` lines
gives one finding per package line (the CSV has no plugin family column, so the package lines
alone mark a vendor advisory check — only local checks print them); every other row with a CVE is
counted in `findings_skipped`. Component = name + version + `rpm`, no purl; `Should be` is the
unattributed fix. On the owner's pair this gives **0 kept of 456**, the same as the `.nessus` road
— which is the point: the CSV is the same scan.

### C3 — The scan date is supplied, because the CSV has none

No column of a Nessus CSV says when the scan ran (`Plugin Publication Date` is the plugin's, not
the scan's). D3 forbids stamping `now`, so a Nessus CSV without `observed_at` on the request is
refused `observed_at_underivable`, exactly as a Cortex CSV with no `last_observed` column is. The
dashboard's upload card gains an "observed at" date field, shown for a `.csv` file.

### C4 — Severity and score

`severity` from the `Risk` column (`None` → empty, N7); `cvss_score` from `CVSS v3.0 Base Score`.
The CSV carries no CVSS vector, so none is written.

### C5 — Nothing about the host

`Host`, `Port`, `Protocol` and the free text are read and dropped (N8). Only the curated document
is stored.

### C6 — Order of the two uploads

The `.nessus` (SBOM) first, the CSV (report) second, both to the same release — D6 enforces it by
name. Because the CSV's package lines and the `.nessus` package list come from one scan, a
finding resolves onto its inventory twin by exact name + version (P3).

### Open gates

| # | gate | why it is open |
| --- | --- | --- |
| P-G1 | **Coverage against a real SBOM.** On one host, compare the CVEs Themis finds from this inventory with those from a syft (or vendor) SBOM of the same host | the missing source package (P5) and the missing `arch` can lose matches; the size of the loss decides whether a source-name table is needed |
| P-G2 | **Other vendors' RPMs** (a database vendor's repo, EPEL) | real CVE surface; needs a vendor → purl-namespace rule per vendor, decided per vendor |
| P-G3 | **Hand-installed software** (the 2026-10-24 gate G3) | next design; plugin outputs carry `Associated Package` / `Managed by OS`, which tells managed from unmanaged installs |
