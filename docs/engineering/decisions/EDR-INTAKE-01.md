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
| 2 | JSON object with `bomFormat: "CycloneDX"` | `sbom` / `cyclonedx` |
| 3 | JSON object with `spdxVersion` | `sbom` / `spdx` |
| 4 | JSON object with `findings: [...]` | `vuln-report` / `curated` |
| 5 | JSON object with `Results: [...]` **and** `SchemaVersion` or `ArtifactName` | `vuln-report` / `trivy` |
| 6 | JSON array whose elements carry Cortex's required field set | `vuln-report` / `cortex-json` |
| 7 | anything else | **refused**, `unrecognised_format` |

**A declared `kind`/`format` that contradicts the body is refused** (`declared_format_mismatch`),
never silently overridden — the caller's assertion is information, and disagreeing with it quietly
is how a mis-declared document becomes a mystery later. Invalid *combinations* are refused the same
way: the matrix is `sbom × {cyclonedx, spdx}` and `vuln-report × {curated, trivy, cortex-json,
cortex-csv}`, and nothing else. `kind=sbom, format=trivy` fails at identification.

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
completion. Honest limit, stated plainly: **there is no single endpoint that says "everything
downstream of this upload is done"**, and this EDR does not pretend to add one. Making that
answerable is a bus-level question (a correlation-complete event keyed to the evidence id), filed as
a follow-up rather than faked here.

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

The reviewer's 20-check contract matrix is adopted as the implementation gate and mapped into
`openspec/changes/phase3-report-intake/tasks.md` group 6.
