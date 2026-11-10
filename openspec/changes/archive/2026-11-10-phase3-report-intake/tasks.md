# Tasks — phase3-report-intake

Source of truth: `docs/engineering/decisions/EDR-INTAKE-01.md`. Every group ends by making
`make vet-tags` green (a tagged file is invisible to the default build and rots silently).

## Group 1 — Detection and the converter registry (D4, D5) — M3's foundation, built first

- [x] 1.1 `internal/evidence/adapters/report/registry.go`: `Detect(contentType string, body []byte)
      (Kind, Dialect, error)` implementing D5's closed table, and a `Converter` port
      `Convert(body []byte, observedAt time.Time) (curated []byte, Stats, error)`.
      Tests: one case per table row **plus** the unrecognised row; the array-shaped Cortex body from
      the 2026-10-05 incident is a named fixture, because it is the regression this change exists for.
- [x] 1.2 `report/curated.go` — pass-through + `scannerRecord` schema validation (the E1 half).
- [x] 1.3 `report/cortex.go` — **ported**, not reimplemented, from
      `scripts/cortex-csv-to-scan-report.sh`. Both containers: CSV (RFC 4180, multi-line quoted
      fields — a 1264-physical-line export is 557 logical rows) and the JSON array. Must carry over
      every judgement the 2026-09-10 case paid for: ecosystem from the purl, the `(\.|\+)el[0-9]`
      RPM-build inference for `APP` rows (KN-SCAN-3b), `origin_package_name` → `component.source`,
      `fix_versions` split on `[;,]` for CSV and taken as a list for JSON, `Unknown` severity → "".
- [x] 1.4 **The equivalence gate (D4).** A fixture corpus under `report/testdata/` and a test that
      runs the **existing Python script** and the Go converter over each fixture and asserts
      **byte-identical** curated output. This gate is the whole reason the port is safe; it closes
      GUI-10. Fixtures must include a real Cortex CSV slice, the JSON array, an `APP`/el8 row, a
      multi-version `fix_versions`, and a row with no purl.
- [x] 1.5 `report/trivy.go` — ported from the browser's `translateTrivy` (EDR-GUI-01 D16), with the
      same equivalence approach (the JS output on committed fixtures is the oracle).
- [x] 1.6 `observedAt` derivation per dialect (D3): Cortex `max(last_observed)` (epoch **ms**),
      Trivy `CreatedAt` when present, curated `max(observed_at)`; **never `now`** —
      `ErrObservedAtUnderivable` when none and none supplied. Property test: `Convert` is pure in
      (bytes, observedAt).

## Group 2 — Domain, app, and the validation taxonomy (D6, D7, D11)

- [x] 2.1 `domain/intake.go`: `RejectReason` as a closed enum (D11's twelve), `Receipt` with its
      state machine (`accepted → validating → converting → registering → filed` | `rejected` |
      `failed`), and `Provenance` gaining `SourceDigest`, `ConvertedBy`, `WithoutSBOM`. Domain
      tests: every transition legal/illegal; a terminal receipt is immutable.
- [x] 2.2 `app/intake.go`: `IntakeService.Intake` in the design's step order (size → detect →
      resolve → convert → schema → SBOM-first → file), with the **first failure winning** and
      **nothing filed until step 7**. New ports: `ReleaseResolver` (D7, read-only) and
      `InventoryReader` (D6). Tests through fakes: one per reason, plus the ordering assertion that
      an invalid-and-early report reports `schema_invalid`, not `no_inventory_for_release`.
- [x] 2.3 `TestIntakeReasonTaxonomyIsClosed` — fails when the enum grows without the spec and the
      dashboard being updated in the same change. #116 cost: a consumer knowing 6 of 15 reasons
      asserted "no reason given" for the other nine.
- [x] 2.4 **`trust.Gate` curated-shape check for `kind=scanner-report`** — the cheap half of E1 on
      the OLD door (`POST /evidence`), so the poison class is unreachable there too. Test: the
      incident body is refused by the gate.

## Group 3 — Persistence and API (D1, D9, D12)

- [x] 3.1 Migration `000003_intake_receipts` (+ down, reversibility is a task gate):
      `intake_receipts(intake_id PK, idempotency_key UNIQUE NULL, status, reason, detail,
      evidence_id NULL, release_id, detected_kind, detected_format, findings_total,
      findings_skipped, components, source_digest, converted_by, created_at, updated_at)`.
      Register `evidence/adapters/store` is already in `scripts/check-coverage.sh`; confirm the tier
      still passes with the new rows.
- [x] 3.2 `api/evidence.openapi.yaml`: `POST /intake` (raw body + query metadata — see the design's
      "why the body is raw"), `GET /intake/{intakeId}`, `IntakeReceipt`, `IntakeProblem` with the
      closed `reason`. Additive only; **`POST /evidence` is unmodified**. Regenerate with
      `make generate-api-evidence` — handlers are generated, never hand-edited.
- [x] 3.3 `adapters/http/intake.go` + routing; `reason` → HTTP status per D11's table;
      `Idempotency-Key` replay returning the original receipt (D12).
- [x] 3.4 `adapters/store/intake.go`: receipt load/save + `THEMIS_INTAKE_RECEIPT_TTL` retention
      sweep (default 30d). Receipts are operational records, **not** evidence — they are deletable.
      Also `FailStaleNonTerminalReceipts`: a receipt advances in the process doing the work, so a
      crash leaves one stuck non-terminal and only the NEXT process can close it out — run at
      startup, named `interrupted by restart; resubmit`.
- [x] 3.5 The `202` slow path (D9): `THEMIS_INTAKE_INLINE_BUDGET` (default `5s`), work continues in a
      bounded worker, receipt advances. Integration test (`-tags=integration`, embedded Postgres):
      a forced-slow intake returns `202`, the receipt reaches `filed`, and the evidence exists.
      The worker is ONE goroutine behind a 64-deep queue, and the fast path does not use it — a
      backlog that is full answers `503` + `Retry-After` and creates **no** receipt, so the whole
      request is safe to retry verbatim.
- [x] 3.6 `next_checks` from `THEMIS_KNOWLEDGE_URL` / `THEMIS_GOVERNANCE_URL` (D10). Absent env →
      the field is **omitted**, never a broken URL.

## Group 4 — Wiring, docs, and retiring the duplicates (D4)

- [x] 4.1 `cmd/evidence`: wire `ReleaseResolver` + `InventoryReader` onto the registry/evidence
      store (the `SubjectRef` precedent, `main.go:103` — same pool, `registry` schema co-locates).
      `deploy/node.env.example` gains the four `THEMIS_INTAKE_*` vars, self-documented (CONVENTIONS R2).
      Verified already done with group 3 (no change needed): `wiring.EvidenceAPI` passes
      `subjectref.NewResolver(cfg.Registry)` as the resolver and the evidence store as the
      `InventoryReader`, and `registryReader` in `cmd/evidence/main.go` is reads-only by
      construction. `deploy/node.env.example` documents THREE `THEMIS_INTAKE_*` vars because
      three are what the binary reads (`MAX_BYTES`, `INLINE_BUDGET`, `RECEIPT_TTL`) — D13's
      `MAX_RECORDS`/`MAX_DEPTH`/`MAX_FIELD` are constants, not env, so documenting a fourth
      would document a knob that does not exist. `THEMIS_KNOWLEDGE_URL`/`THEMIS_GOVERNANCE_URL`
      (D10) are documented in the same block.
- [x] 4.2 `scripts/cortex-csv-to-scan-report.sh` → thin wrapper that POSTs to intake, **same name
      and CLI** so documented procedures survive. Only after 1.4 is green.
      Its Python moved **verbatim** to `report/testdata/oracle/cortex_csv_to_scan_report.py` as a
      frozen test oracle (with a README saying it is on no operator road) and 1.4's live
      equivalence run now execs it there — so the byte-equality gate survives the rewiring
      instead of being retired with the script.
- [x] 4.3 Dashboard: upload posts to intake; **delete** the D16 in-browser translators; keep the
      file-note UX by reading `findings_total`/`findings_skipped`/`detected_format` from the
      response. `make js-check` green.
      `translateTrivy` + `TRIVY_ECOSYSTEMS` + `detectTranslator` are gone; the translator moved
      verbatim to `report/testdata/oracle/translate_trivy.js`, where 1.5's oracle now runs it
      (it used to be extracted from `app.js`, which deleting the function would have broken).
      Uploads go through the dashboard's own proxy (EDR-GUI-01 D1/D4) — `/api/evidence/intake` is
      now a `documentPosts` route, so a multi-megabyte body streams instead of hitting the 1 MiB
      identity buffer (GUI-14). A refusal renders `reason` and `detail` as TWO fields. A **VEX**
      still takes `POST /evidence`: intake's D5a table does not name that kind, and a door that
      cannot identify a document must refuse it rather than guess.
- [x] 4.4 `scripts/gf-upload-sbom.sh` → one intake call per document, keeping `-r` (reuse release).
      The JSON envelope and its temp file are gone (the body is the artifact), both scripts send
      `X-API-Key` from `THEMIS_API_KEY` when it is set, and every write uses `--fail-with-body` so
      a refusal's `reason`/`detail` reaches the operator instead of being swallowed by `-f`.
- [x] 4.5 TESTING.md § scanner reports rewritten around intake, with the design's curl commands;
      INSTALLATION.md and API.md updated. BACKLOG: close **GUI-16b**, **GUI-10**, **E11**, and E1
      for the intake path (E1 stays open for non-scanner kinds on the old door until 2.4 lands).
      E1 is recorded as **partly** closed in PARITY-GAP: the unreadable-document class is refused
      by name at the border (and 2.4 put the same check on the old door), while validation against
      the embedded CycloneDX/SPDX/OpenVEX/CSAF schemas is the half still open. GUI-10 closed **by
      removal** — there is no JavaScript converter left to test — and GUI-15 was re-shaped to name
      a Go `Converter` rather than a browser translator.
- 4.6 → moved to `phase3-pending-tests` (section 1).

**Moved 2026-11-10:** 4.6 and Groups 5–9 (the live checks, the test matrix and the D10 follow-through) now live in `phase3-pending-tests`, so this change could be archived with its built code.

## Dependencies and sequencing

- **M1 = groups 1 (minus 1.5), 2, 3.1–3.3, 4.1, 4.5.** This alone closes the incident class.
- **M2 = 3.4–3.6.** Receipts and the slow path.
- **M3 = 1.5, 4.2–4.4.** Converter consolidation. Until it lands, duplicate converters exist and
  TESTING.md's one-converter rule is enforced by review rather than by construction — acceptable
  for one milestone, not indefinitely.
- **1.4 gates 4.2.** Do not rewire the script before the Go converter is proven byte-equivalent;
  that ordering is what keeps the 2026-09-10 false-positive class from recurring with better
  ergonomics.
