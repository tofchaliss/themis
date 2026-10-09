# Tasks — phase3-report-intake

Source of truth: `docs/engineering/decisions/EDR-INTAKE-01.md`. Every group ends by making
`make vet-tags` green (a tagged file is invisible to the default build and rots silently).

## Group 1 — Detection and the converter registry (D4, D5) — M3's foundation, built first

- [ ] 1.1 `internal/evidence/adapters/report/registry.go`: `Detect(contentType string, body []byte)
      (Kind, Dialect, error)` implementing D5's closed table, and a `Converter` port
      `Convert(body []byte, observedAt time.Time) (curated []byte, Stats, error)`.
      Tests: one case per table row **plus** the unrecognised row; the array-shaped Cortex body from
      the 2026-10-05 incident is a named fixture, because it is the regression this change exists for.
- [ ] 1.2 `report/curated.go` — pass-through + `scannerRecord` schema validation (the E1 half).
- [ ] 1.3 `report/cortex.go` — **ported**, not reimplemented, from
      `scripts/cortex-csv-to-scan-report.sh`. Both containers: CSV (RFC 4180, multi-line quoted
      fields — a 1264-physical-line export is 557 logical rows) and the JSON array. Must carry over
      every judgement the 2026-09-10 case paid for: ecosystem from the purl, the `(\.|\+)el[0-9]`
      RPM-build inference for `APP` rows (KN-SCAN-3b), `origin_package_name` → `component.source`,
      `fix_versions` split on `[;,]` for CSV and taken as a list for JSON, `Unknown` severity → "".
- [ ] 1.4 **The equivalence gate (D4).** A fixture corpus under `report/testdata/` and a test that
      runs the **existing Python script** and the Go converter over each fixture and asserts
      **byte-identical** curated output. This gate is the whole reason the port is safe; it closes
      GUI-10. Fixtures must include a real Cortex CSV slice, the JSON array, an `APP`/el8 row, a
      multi-version `fix_versions`, and a row with no purl.
- [ ] 1.5 `report/trivy.go` — ported from the browser's `translateTrivy` (EDR-GUI-01 D16), with the
      same equivalence approach (the JS output on committed fixtures is the oracle).
- [ ] 1.6 `observedAt` derivation per dialect (D3): Cortex `max(last_observed)` (epoch **ms**),
      Trivy `CreatedAt` when present, curated `max(observed_at)`; **never `now`** —
      `ErrObservedAtUnderivable` when none and none supplied. Property test: `Convert` is pure in
      (bytes, observedAt).

## Group 2 — Domain, app, and the validation taxonomy (D6, D7, D11)

- [ ] 2.1 `domain/intake.go`: `RejectReason` as a closed enum (D11's twelve), `Receipt` with its
      state machine (`accepted → validating → converting → registering → filed` | `rejected` |
      `failed`), and `Provenance` gaining `SourceDigest`, `ConvertedBy`, `WithoutSBOM`. Domain
      tests: every transition legal/illegal; a terminal receipt is immutable.
- [ ] 2.2 `app/intake.go`: `IntakeService.Intake` in the design's step order (size → detect →
      resolve → convert → schema → SBOM-first → file), with the **first failure winning** and
      **nothing filed until step 7**. New ports: `ReleaseResolver` (D7, read-only) and
      `InventoryReader` (D6). Tests through fakes: one per reason, plus the ordering assertion that
      an invalid-and-early report reports `schema_invalid`, not `no_inventory_for_release`.
- [ ] 2.3 `TestIntakeReasonTaxonomyIsClosed` — fails when the enum grows without the spec and the
      dashboard being updated in the same change. #116 cost: a consumer knowing 6 of 15 reasons
      asserted "no reason given" for the other nine.
- [ ] 2.4 **`trust.Gate` curated-shape check for `kind=scanner-report`** — the cheap half of E1 on
      the OLD door (`POST /evidence`), so the poison class is unreachable there too. Test: the
      incident body is refused by the gate.

## Group 3 — Persistence and API (D1, D9, D12)

- [ ] 3.1 Migration `000003_intake_receipts` (+ down, reversibility is a task gate):
      `intake_receipts(intake_id PK, idempotency_key UNIQUE NULL, status, reason, detail,
      evidence_id NULL, release_id, detected_kind, detected_format, findings_total,
      findings_skipped, components, source_digest, converted_by, created_at, updated_at)`.
      Register `evidence/adapters/store` is already in `scripts/check-coverage.sh`; confirm the tier
      still passes with the new rows.
- [ ] 3.2 `api/evidence.openapi.yaml`: `POST /intake` (raw body + query metadata — see the design's
      "why the body is raw"), `GET /intake/{intakeId}`, `IntakeReceipt`, `IntakeProblem` with the
      closed `reason`. Additive only; **`POST /evidence` is unmodified**. Regenerate with
      `make generate-api-evidence` — handlers are generated, never hand-edited.
- [ ] 3.3 `adapters/http/intake.go` + routing; `reason` → HTTP status per D11's table;
      `Idempotency-Key` replay returning the original receipt (D12).
- [ ] 3.4 `adapters/store/intake.go`: receipt load/save + `THEMIS_INTAKE_RECEIPT_TTL` retention
      sweep (default 30d). Receipts are operational records, **not** evidence — they are deletable.
- [ ] 3.5 The `202` slow path (D9): `THEMIS_INTAKE_INLINE_BUDGET` (default `5s`), work continues in a
      bounded worker, receipt advances. Integration test (`-tags=integration`, embedded Postgres):
      a forced-slow intake returns `202`, the receipt reaches `filed`, and the evidence exists.
- [ ] 3.6 `next_checks` from `THEMIS_KNOWLEDGE_URL` / `THEMIS_GOVERNANCE_URL` (D10). Absent env →
      the field is **omitted**, never a broken URL.

## Group 4 — Wiring, docs, and retiring the duplicates (D4)

- [ ] 4.1 `cmd/evidence`: wire `ReleaseResolver` + `InventoryReader` onto the registry/evidence
      store (the `SubjectRef` precedent, `main.go:103` — same pool, `registry` schema co-locates).
      `deploy/node.env.example` gains the four `THEMIS_INTAKE_*` vars, self-documented (CONVENTIONS R2).
- [ ] 4.2 `scripts/cortex-csv-to-scan-report.sh` → thin wrapper that POSTs to intake, **same name
      and CLI** so documented procedures survive. Only after 1.4 is green.
- [ ] 4.3 Dashboard: upload posts to intake; **delete** the D16 in-browser translators; keep the
      file-note UX by reading `findings_total`/`findings_skipped`/`detected_format` from the
      response. `make js-check` green.
- [ ] 4.4 `scripts/gf-upload-sbom.sh` → one intake call per document, keeping `-r` (reuse release).
- [ ] 4.5 TESTING.md § scanner reports rewritten around intake, with the design's curl commands;
      INSTALLATION.md and API.md updated. BACKLOG: close **GUI-16b**, **GUI-10**, **E11**, and E1
      for the intake path (E1 stays open for non-scanner kinds on the old door until 2.4 lands).
- [ ] 4.6 `make check` green; `openspec archive phase3-report-intake --skip-specs -y`.

## Group 5 — Live verification on the estate (the gate that has caught every real defect)

- [ ] 5.1 Re-run the **2026-10-05 body** through intake on the VM: it must be converted and filed
      (427/427), or refused by name — never filed unreadable.
- [ ] 5.2 Cortex CSV and Cortex JSON of the same scan → **byte-identical** curated document, one
      evidence id, `created=false` on the second (D3 determinism, D8 dedup).
- [ ] 5.3 Report before SBOM → `409 no_inventory_for_release`; with `allow_without_sbom=true` →
      filed, and provenance says so.
- [ ] 5.4 A large report over the inline budget → `202`, receipt polled to `filed`.
- [ ] 5.5 `scripts/vm-verify.sh` clean afterwards, **and** the evidence stream not halted — the
      failure mode this change exists to make impossible.

## Dependencies and sequencing

- **M1 = groups 1 (minus 1.5), 2, 3.1–3.3, 4.1, 4.5.** This alone closes the incident class.
- **M2 = 3.4–3.6.** Receipts and the slow path.
- **M3 = 1.5, 4.2–4.4.** Converter consolidation. Until it lands, duplicate converters exist and
  TESTING.md's one-converter rule is enforced by review rather than by construction — acceptable
  for one milestone, not indefinitely.
- **1.4 gates 4.2.** Do not rewire the script before the Go converter is proven byte-equivalent;
  that ordering is what keeps the 2026-09-10 false-positive class from recurring with better
  ergonomics.

## Group 6 — The intake contract test matrix (review gate, 2026-10-09)

Adopted verbatim from the architecture review as the **implementation approval gate**. Every check
is a test, not a manual step. Grouped as the review grouped them; the EDR decision each one defends
is named so a failing check points at a contract, not just a line.

### Format identification (D5a)

- [ ] 6.1 Valid SPDX JSON and CycloneDX JSON are identified as SBOMs.
- [ ] 6.2 Valid Trivy JSON, Cortex JSON and Cortex CSV are each identified as their own dialect.
- [ ] 6.3 A declared `kind`/`format` contradicting the body → `declared_format_mismatch`, **never a
      silent override**. Includes the invalid combination `kind=sbom, format=trivy`.
- [ ] 6.4 Unknown vendor JSON, unknown CSV, a JSON object with `spdxVersion` but no SPDX structure,
      and an ambiguous body are each refused — `unrecognised_format` or `source_invalid`, never
      admitted as "probably a scanner report".

### Cardinality and conversion (D5b, CONVENTIONS R5)

- [ ] 6.5 An **empty** Cortex array is refused (`empty_report`) **without indexing element zero** —
      the 0/1/>1 cardinalities, and 0 is the one that panics.
- [ ] 6.6 One-row and multi-row CSV reports preserve the expected finding count.
- [ ] 6.7 A malformed row can neither silently disappear nor become an accepted finding: it is
      counted in `findings_skipped` **and** the structure that contained it passed D5b. A report
      malformed at element 47 but valid at element 0 is refused, not skipped-and-filed.
- [ ] 6.8 Missing, duplicate and ambiguous component identities preserve EDR-IDENTITY-01 D6:
      exactly-one match resolves, anything else **abstains**. No invented identities.

### Timestamp and idempotency (D3)

- [ ] 6.9 Same bytes + same effective timestamp → byte-identical output (property test: `Convert`
      is pure in `(bytes, observedAt)`).
- [ ] 6.10 No derivable timestamp and none supplied → `observed_at_underivable`. Present but
      unparseable or implausible → `observed_at_invalid`.
- [ ] 6.11 An identical resubmission creates **no** duplicate evidence: the `(source_digest,
      release_id)` lookup hits before conversion, `created=false`, `dedup_basis=source_digest`.
- [ ] 6.12 A genuinely new observation of the same artifact is **not** suppressed as a retry
      (`created=true`), and **the same source after a converter-version bump still dedups** —
      the defect the review found. `force_reconvert=true` is the only way to refile it.

### Inventory and processing (D6, D10)

- [ ] 6.13 No SBOM for the release → `no_inventory_for_release`, naming what to upload first.
- [ ] 6.14 **No `inventory_not_ready` state exists** — asserted, not assumed: a test proves the
      inventory is queryable in the same transaction the SBOM is filed in, so the reason is
      deliberately absent from the enum. If SBOM parsing ever becomes async, this test fails first.
- [ ] 6.15 An inventory belonging to a **different release** cannot satisfy the precondition.
- [ ] 6.16 A successful upload is distinguishable from downstream completion: a terminal receipt
      says `filed`, **never** "correlated", and carries `next_checks`.

### Immutability and recovery (D13)

- [ ] 6.17 Invalid input creates **no** evidence row and **no** outbox note — only a `rejected`
      receipt.
- [ ] 6.18 A conversion failing part-way through a large report leaves no partial evidence.
- [ ] 6.19 A duplicate upload follows the existing idempotent path (`200`, `created=false`), and
      byte-identical content aimed at a **different** release still refuses loudly with
      `duplicate_other_release`.
- [ ] 6.20 A downstream consumer failure after a valid upload is observable **and does not
      masquerade as an upload failure**: the receipt stays `filed`. (The consumer-side half of this
      is `OBS-HALT-1`, tracked separately — intake must not paper over it.)

**Approval gate:** all twenty green, plus group 1.4's byte-equality corpus and group 5's live
estate round. 6.5, 6.7 and 6.12 are the three that encode defects already paid for; if time
pressure forces triage, those three are not negotiable.

## Group 7 — The three verification points (review, second pass 2026-10-09)

Raised as pre-publication conditions on D3/D3a/D5b. Each is a test, and each defends a property
that a happy-path demo would not exercise.

- [ ] 7.1 **Concurrency, not just speed (D3).** `UNIQUE (fingerprint)` already exists; add the
      **partial** `UNIQUE (provenance_source_digest, subject_release_id, provenance_observed_at)
      WHERE provenance_source_digest <> ''` in the intake migration. Integration test
      (`-tags=integration`): **N concurrent identical submissions** of one converted source →
      exactly **one** evidence row, every caller receiving the same `evidence_id` with
      `created=false` for the losers. The write path must be `INSERT … ON CONFLICT`; a test that
      passes only because the goroutines happened not to interleave is not this test — drive it
      with a barrier.
- [ ] 7.2 **Same source, different supplied `observed_at` (D3).** Must **not** dedup: two evidence
      documents, because the caller asserted two distinct observations. Twin case: same source with
      a **derived** timestamp twice → dedups, since derivation is pure in the bytes.
- [ ] 7.3 **`force_reconvert` creates a generation, never mutates (D3a).** Under a bumped converter
      version: `201`, a **new** evidence id, and the prior document still present and byte-unchanged
      (assert its fingerprint and `filed_at`). Under an unchanged converter: `200`,
      `created=false`, `dedup_basis=content_fingerprint`, and the `detail` says reconversion
      produced identical bytes. Assert explicitly that **no row was updated or deleted** — this is
      an immutable store and the test is what keeps it one.
- [ ] 7.4 **The accepted-input contract matches the maintained converter (D5b).** A table-driven
      test over every row of D5b's table. The skip row must be exactly the script's line 77
      condition (`not cve or not (purl or name)`) and the coercion rows must match `num()`,
      `Unknown`→`""`, and empty `fix_versions` — asserted against the **script's own output** on the
      same fixtures, so the contract cannot drift from the oracle in either direction.
- [ ] 7.5 **Element 47 is a regression fixture, not a validation case (D5b).**
      `report/testdata/cortex-json-malformed-at-47.json` — the real 2026-10-05 export with element
      47 structurally broken and element 0 valid, committed with a provenance note. Asserts
      `source_invalid` naming index **47**. A general "invalid input is refused" test passes without
      ever reaching element 47, which is exactly how this class survived the first draft.
