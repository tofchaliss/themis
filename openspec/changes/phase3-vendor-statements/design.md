# Design — phase3-vendor-statements

## The statement, extended

`domain.Applicability{Package, Status, Justification, Scope, Advisory, FixedVersion}`. The struct
stays comparable (strings and a value-object scope), so the set union, the scope-less-twin drop
and the view-equality check in `reconcile.go` keep working unchanged; `sortedApplicabilities`
gains the two fields as the final tiebreak so the order is total. `NewApplicabilityProposal`
validates `Status` against the closed set and refuses anything else by name.

## The feed

`redhat_client.go`:

- `package_state[]`: every row with a package-level name becomes a statement. `fix_state` maps
  through one table (D13); an unmapped state is refused by the constructor and logged by the
  caller, never silently skipped. Dedup key `package + lower(cpe) + status`.
- `affected_release[]` main-stream rows: beside the existing fix-version fold, each becomes a
  `fixed` statement with `Advisory`, `FixedVersion` (the row's package NEVRA, or the module id
  with the resolved source NEVRAs still in `Fixes`), and `Scope: ScopeFromCPE(ar.CPE)`.

## Restatement against the set (D17)

`faultline.go` `repeatsLatestFrom`: for an applicability proposal, compare against every recorded
proposal from the same source and kind; equal content anywhere is a restatement. Vuln-facts
proposals keep the latest-only rule.

## The event and the wire

- FaultlineEnriched: `Applicabilities[].Advisory`, `.FixedVersion` (JSON schema: two optional
  string properties; `additionalProperties:false` stays).
- Knowledge read API `Applicability`: `status` becomes an enum of the closed set; `advisory`,
  `fixed_version` added. Regenerate.
- Governance `VendorStatement`: same two fields; `status` enum. Regenerate.
- Governance inbound consumer DTO and the Knowledge client map the two fields.

## Governance

`reactToApplicability` and `coveringStatement` untouched in logic (filter on `not_affected`).
`vendorStatements` in `assessment.go` returns the full list as today; the ORDER is the GUI's.

## The GUI

`vendorStatementsSection`: partition by applicability; render applicable rows first with a
status chip per status (`fixed` shows `advisory · build`), fold the rest under
`<details>` "N statements about other products", and when the release scope is known and the
applicable set is empty render the explicit sentence (D16). `applicabilityChip` unchanged.

## Script

`scripts/vex-reject-inapplicable.sh`: `select(.status == "not_affected")` before the
applicability read.

## Regression outcomes (validation 7, 8)

Fixture Hydra documents under `internal/knowledge/adapters/feed/testdata/redhat/`:
`cve-2022-30632.json` (RHEL 8 fixed + will-not-fix, RHEL 9 not-affected, non-OS products),
`rhel9-only.json`, `no-row-for-family.json`. One test per outcome at the feed, and one
end-to-end test in Governance's assessment over the three.
