# Tasks — phase3-vendor-statements

Markers: **[API]** changes a wire contract (regenerate, never hand-edit `gen/`) · **[SCHEMA]**
changes a stored or event shape. Every group ends with `make vet-tags` and `make check` green
locally; CI runs `make check-ci`. No `specs/` deltas — archive with
`openspec archive phase3-vendor-statements --skip-specs -y`.

## Group 1 — Knowledge: the statement, the feed, the card (D13, D14, D17)

- [x] **1.1 — The closed status set and the two fields.** `internal/knowledge/domain/proposal.go`:
  `Applicability` gains `Advisory`, `FixedVersion`; `NewApplicabilityProposal` validates `Status`
  against `ApplicabilityStatuses` and refuses others by name. `reconcile.go`
  `sortedApplicabilities` tiebreaks on the new fields. Tests: `proposal_test.go` (refusal names the
  value; every listed status accepted), `reconcile_internal_test.go` (sort is total with the fields).
- [x] **1.2 — Restatement against the set.** `domain/faultline.go` `repeatsLatestFrom`: an
  applicability proposal equal in content to ANY recorded proposal from the same source is a
  restatement. Test: three statements folded twice yield three proposals, not six.
- [x] **1.3 — Red Hat: every package_state row, every main-stream fixed row.**
  `adapters/feed/redhat_client.go`: the fix_state table; `fixed` statements from
  `affected_release` with advisory, NEVRA and scope; dedup key gains the status. Tests on the three
  fixture documents (CVE-2022-30632 as a Hydra fixture, RHEL-9-only, no-row-for-family):
  statuses, scopes, advisory and build as expected; `not_affected` behaviour unchanged.
- [x] **1.4 — [SCHEMA] Persistence and the event.** `adapters/store/codec.go` view and proposal
  DTOs; `domain/event.go` FaultlineEnriched; `schemas/knowledge.faultline_enriched.v1.schema.json`
  two optional strings. Tests: codec round-trip of both fields; contract test green.
- [x] **1.5 — [API] Knowledge read API.** `api/knowledge.openapi.yaml` `Applicability.status` enum
  + `advisory` + `fixed_version`; `make generate-api-knowledge`; handler mapping. Test:
  `TestGetFaultline_CarriesVendorScope` extended with a `fixed` statement.
- [x] **1.6 — Gate.** `make vet-tags`, `make check` green.

## Group 2 — Governance: carry, expose, act unchanged (D15)

- [x] **2.1 — Carry the fields.** `app.Applicability` + `adapters/inbound/consumer.go` DTO +
  `adapters/knowledge/client.go`. Tests: consumer and client map `advisory`/`fixed_version`.
- [x] **2.2 — Act unchanged, proven.** `service_applicability_test.go`: a `fixed` and a
  `will_not_fix` statement, both `applicable`, raise NO proposal; a `not_affected` still does. The
  CVE-2026-33006 fixture with a `fixed` statement stays open.
- [x] **2.3 — [API] Governance read API.** `api/governance.openapi.yaml` `VendorStatement.status`
  enum + `advisory` + `fixed_version`; `make generate-api-governance`; handler mapping. Test: a
  handler test for `vendor_statements` (none exists today) over the three outcomes.
- [x] **2.4 — Gate.** `make vet-tags`, `make check` green.

## Group 3 — GUI and script (D16)

- [x] **3.1 — The drawer.** `cmd/dashboard/static/app.js` `vendorStatementsSection`: applicable
  first with per-status chips (`fixed` shows advisory · build), others folded under one
  `<details>`, the explicit no-statement sentence when the release is placeable and nothing
  applies. `make js-check` green.
- [x] **3.2 — The script.** `scripts/vex-reject-inapplicable.sh` filters `status == "not_affected"`.
  Replay-seam test with a `fixed` applicable statement: not rejected.
- [x] **3.3 — Docs.** CLAUDE.md "Key invariants" VEX bullet; TESTING.md vendor-statement section;
  BACKLOG item closed.

## Group 4 — Verification

- [x] **4.1 — End to end.** Governance assessment test over the three fixtures (validation 7).
- [ ] **4.2 — VM round.** Deploy; open CVE-2022-30632 on the Rocky 8.10 release: the RHEL 8 `fixed`
  rows read "applies here" with their advisories; the RHEL 9 / OpenStack rows are folded; open a
  binutils finding: `will_not_fix` for RHEL 8 applies. Record in `docs/engineering/vm-test-2026-10-14.md`.
- [ ] **4.3 — Archive.** `openspec archive phase3-vendor-statements --skip-specs -y`.

## Out of scope

- Changing which statuses may raise a proposal (D15 keeps `not_affected` only).
- Non-Red Hat feed vocabularies beyond accepting the closed set.
- Any change to the verdict engine or `VulnFacts.Fixes`.
