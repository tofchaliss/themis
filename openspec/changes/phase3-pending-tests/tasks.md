# Tasks — phase3-pending-tests

No `specs/` deltas — archive with `openspec archive phase3-pending-tests --skip-specs -y`.

Each task below was moved here **verbatim** from the change named in its section, on 2026-11-10,
so that change could be archived with its built code. The task numbers keep their original
numbering, so a reference in an EDR or a PR still finds them.

## Section 1 — from `phase3-report-intake` (EDR-INTAKE-01)

The intake door (`POST /intake`, groups 1–4) is built and merged (#138–#141). What is left is
proof: the gate, the live estate round, the contract test matrix, and the D10 follow-through.

- [ ] 4.6 `make check` green.

### Group 5 — Live verification on the estate (the gate that has caught every real defect)

- [ ] 5.1 Re-run the **2026-10-05 body** through intake on the VM: it must be converted and filed
      (427/427), or refused by name — never filed unreadable.
- [ ] 5.2 Cortex CSV and Cortex JSON of the same scan → **byte-identical** curated document, one
      evidence id, `created=false` on the second (D3 determinism, D8 dedup).
- [ ] 5.3 Report before SBOM → `409 no_inventory_for_release`; with `allow_without_sbom=true` →
      filed, and provenance says so.
- [ ] 5.4 A large report over the inline budget → `202`, receipt polled to `filed`.
- [ ] 5.5 `scripts/vm-verify.sh` clean afterwards, **and** the evidence stream not halted — the
      failure mode this change exists to make impossible.

### Group 6 — The intake contract test matrix (review gate, 2026-10-09)

Adopted verbatim from the architecture review as the **implementation approval gate**. Every check
is a test, not a manual step. Grouped as the review grouped them; the EDR decision each one defends
is named so a failing check points at a contract, not just a line.

#### Format identification (D5a)

- [ ] 6.1 Valid SPDX JSON and CycloneDX JSON are identified as SBOMs.
- [ ] 6.2 Valid Trivy JSON, Cortex JSON and Cortex CSV are each identified as their own dialect.
- [ ] 6.3 A declared `kind`/`format` contradicting the body → `declared_format_mismatch`, **never a
      silent override**. Includes the invalid combination `kind=sbom, format=trivy`.
- [ ] 6.4 Unknown vendor JSON, unknown CSV, a JSON object with `spdxVersion` but no SPDX structure,
      and an ambiguous body are each refused — `unrecognised_format` or `source_invalid`, never
      admitted as "probably a scanner report".

#### Cardinality and conversion (D5b, CONVENTIONS R5)

- [ ] 6.5 An **empty** Cortex array is refused (`empty_report`) **without indexing element zero** —
      the 0/1/>1 cardinalities, and 0 is the one that panics.
- [ ] 6.6 One-row and multi-row CSV reports preserve the expected finding count.
- [ ] 6.7 A malformed row can neither silently disappear nor become an accepted finding: it is
      counted in `findings_skipped` **and** the structure that contained it passed D5b. A report
      malformed at element 47 but valid at element 0 is refused, not skipped-and-filed.
- [ ] 6.8 Missing, duplicate and ambiguous component identities preserve EDR-IDENTITY-01 D6:
      exactly-one match resolves, anything else **abstains**. No invented identities.

#### Timestamp and idempotency (D3)

- [ ] 6.9 Same bytes + same effective timestamp → byte-identical output (property test: `Convert`
      is pure in `(bytes, observedAt)`).
- [ ] 6.10 No derivable timestamp and none supplied → `observed_at_underivable`. Present but
      unparseable or implausible → `observed_at_invalid`.
- [ ] 6.11 An identical resubmission creates **no** duplicate evidence: the `(source_digest,
      release_id)` lookup hits before conversion, `created=false`, `dedup_basis=source_digest`.
- [ ] 6.12 A genuinely new observation of the same artifact is **not** suppressed as a retry
      (`created=true`), and **the same source after a converter-version bump still dedups** —
      the defect the review found. `force_reconvert=true` is the only way to refile it.

#### Inventory and processing (D6, D10)

- [ ] 6.13 No SBOM for the release → `no_inventory_for_release`, naming what to upload first.
- [ ] 6.14 **No `inventory_not_ready` state exists** — asserted, not assumed: a test proves the
      inventory is queryable in the same transaction the SBOM is filed in, so the reason is
      deliberately absent from the enum. If SBOM parsing ever becomes async, this test fails first.
- [ ] 6.15 An inventory belonging to a **different release** cannot satisfy the precondition.
- [ ] 6.16 A successful upload is distinguishable from downstream completion: a terminal receipt
      says `filed`, **never** "correlated", and carries `next_checks`.

#### Immutability and recovery (D13)

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

### Group 7 — The three verification points (review, second pass 2026-10-09)

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

### Group 8 — The two approval proof obligations (review, third pass 2026-10-09)

The reviewer's standing condition: **evidence for the uniqueness-conflict response path, and for the
downstream effects of deliberate reconversion.** Neither is satisfied by a declaration. Approval is
gated on these, and the principle the review generalized applies throughout — *test the specific
counterexample that motivated the rule, not a broad success or failure condition*.

#### 8.1–8.2 The uniqueness-conflict response path (D3)

- [ ] 8.1 **A source-digest conflict must read as an ordinary duplicate, not a persistence
      failure.** Today `Save` resolves the benign case via `errors.Is(err, pgx.ErrNoRows)`
      (`store.go:82`) and sends everything else to `case err != nil` (`store.go:97`) as
      `"evidence: insert: …"`. A `23505` on the new constraint lands there — **a 500 where the API
      contract requires `200 created=false`.** Implement the constraint-name dispatch in D3 and
      test it with a **differing fingerprint**, which is the only case the existing handler cannot
      reach: same source bytes, same release, same resolved `observed_at`, converter bumped so the
      curated output differs. Expected: `200`, the existing `evidence_id`, `dedup_basis =
      source_digest`. The counterexample, not a generic duplicate test.
- [ ] 8.2 **The partial index must be inferable, and the conflict target must be the intended
      one.** Create it as a **named** partial unique index
      (`evidence_source_digest_release_observed_key … WHERE provenance_source_digest <> ''`) and
      assert against real PostgreSQL (`-tags=integration`) that: (a) a statement targeting it
      **without** restating the `WHERE` predicate fails to infer and errors — proving the predicate
      is load-bearing rather than decorative; (b) the dispatch keys on
      `PgError.ConstraintName`, so a future third constraint cannot be silently absorbed into the
      source-digest branch; (c) pass-through rows (empty `source_digest`) are **outside** the index
      and unaffected, which is what keeps `POST /evidence` behaviour unchanged.

#### 8.3–8.4 Downstream effects of deliberate reconversion (D3a)

- [ ] 8.3 **Occurrence cardinality across a reconversion — the measurement, not the assertion.**
      `faultline_matches` is keyed `(release_id, faultline_id, component_purl)` with **no evidence
      id** (`000001_knowledge.up.sql:53`), so the two cases must be measured separately through the
      full pipeline, not reasoned about:
      - converter change that leaves identity derivation alone → occurrence count **unchanged**
        (tuples collapse onto existing rows; re-processing is idempotent).
      - converter change that **alters** purl or ecosystem derivation → occurrence count **rises**,
        old rows stay active, both identities live on the same card and release.
      Record the before/after counts of `faultline_matches` and `COUNT(DISTINCT component_purl)`
      per `(release, faultline)`. The second case is KN-SCAN-4(b)'s shape — 87 of 87 rows on P1
      2026-09-17 — and is the *usual* reason a converter gets bumped, so it is the case that must be
      measured rather than the comfortable one.
- [ ] 8.4 **Nothing is retired implicitly.** Assert that a reconversion sets no
      `faultline_matches.retired_at`: retirement is *asserted, never inferred*
      (`000010_match_retired.up.sql`), so a new generation must not quietly supersede the old one.
      Then document, in TESTING.md beside the intake procedure, that `force_reconvert` is **not**
      routine remediation and that its occurrence delta is checked afterwards — the operational half
      of D3a, which no test can supply.

**Both obligations are open.** Until 8.1–8.2 are green the conflict path is specified and unproven;
until 8.3 is measured on a real estate, `force_reconvert` stays out of documented remediation
procedure. Neither blocks M1, which does not ship `force_reconvert`.

### Group 9 — D10 correction follow-through (2026-10-09, post-merge)

D10's "no correlation-complete signal exists" limit was stale on the day this change merged: PR #129
shipped `knowledge.release_correlation_completed.v1` on 2026-10-07, keyed by `sbom_id`. Verified
**SBOM-only** — one non-test caller (`app/correlate.go:314`), nothing in `app/scanner.go:274`.

- [ ] 9.1 **M2's receipt consumes the event for SBOMs instead of telling the client to poll.** A
      receipt for `kind: sbom` can reach a real `correlated` state. Needs a decision first on **who
      relays** the event to the receipt: Evidence must not poll Knowledge (D10's coupling argument
      stands), so the relay is Governance's or a dedicated consumer's. **Blocked on 9.3.**
- [ ] 9.2 **`next_checks` is the fallback, not the default.** Emit it for the kinds with no event
      (`vuln-report`, `vex`); for `sbom`, name the event. Test: a receipt for an SBOM and a receipt
      for a report carry **different** completion mechanisms, so a client cannot assume one.
- [ ] 9.3 **OPEN QUESTION for the owner of EDR-DELIVERY-01 N-M2** — should
      `ScannerReportService.ApplyIngest` publish the same event (`cause` extended, or a sibling
      event)? That would make `correlated` uniform across kinds and remove the polling fallback
      entirely. Not proposed here: the event's schema says it describes one SBOM, and widening a
      published integration-contract v1 belongs to its author. **This is the question that decides
      whether 9.1 and 9.2 are two code paths or one.**

## Section 2 — from `phase3-decision-scope-s1` (EDR-SYNC-01 step S1)

The scope API (S1, #223) passed its VM round on 2026-11-03. The GUI scope picker (#226) has not
had its VM check yet.

- [ ] 4.3 VM: open a finding on a release whose CVE is open on other projects; pick scope
  product; the preview lists the sibling projects by name; Raise & accept; the sibling's drawer
  shows "applied from another release" and the scoped proposal within a minute.

## Gate

- [ ] G.1 `make check` green after the last test lands; then archive this change.
