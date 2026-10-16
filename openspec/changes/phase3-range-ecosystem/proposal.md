# Proposal — phase3-range-ecosystem (EDR-KNOWLEDGE-01 amendment D13–D14, 2026-10-16)

## Why

Four of the seventeen stdlib CVEs still open on the estate after the KN-GO arc would clear on
their Go range but stayed open because the card's reconciled range list also held ranges published
for OTHER products of the same CVE, and the version-range rule read the list as one union. The
kernel range type carries an ecosystem; the card dropped it.

## What changes

- **Knowledge** carries `RangeStatements {ecosystem, package, range}` beside the flat
  `AffectedRanges` through the proposal log, the reconciled view, the enriched event and the read
  API (`affected_range_statements`). OSV fills them; the flat list stays the union.
- **Verdicts read a component's world**: `EnterpriseView.RangesFor` / `value.SelectRanges` at
  match time and in Governance's `ProvablyOutOfRange` (the re-judge pass included).

## What does NOT change

- The flat list, its display, the trust grading, the auto-accept policy, the event version.
- Cards with no statements: judged on the flat list exactly as before.

## Decision record

EDR-KNOWLEDGE-01 D13–D14; EDR-TRUST-01 note. No `specs/` deltas; archive with `--skip-specs`.
