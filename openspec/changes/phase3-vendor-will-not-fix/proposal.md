# Proposal — phase3-vendor-will-not-fix (EDR-VEX-02 amendment D18–D21, 2026-10-16)

## Why

The per-package census after the vendor-statement work showed that nearly every open CVE of the
scanner-reported packages on the estate (binutils, compat-libtiff3, libtiff, curl) is marked
`will_not_fix` or `fix_deferred` by Red Hat for RHEL 8. Those Findings are open correctly, and
each one waits in the queue for a person to type `accepted_risk` and the vendor's own words as the
reason — over a hundred times on one estate. The statement is shown (D15) but the stance it calls
for is not proposed.

## What changes

- **Governance** raises a system `accepted_risk` proposal (`vexwnf:<finding>:<package-key>`,
  Asserted) for an applicable `will_not_fix` / `fix_deferred` / `out_of_support` statement, with
  the vendor's status and justification as the rationale. Never auto-accepted.
- **The disposition watcher** re-surfaces a Finding whose Position accepted such a proposal when
  an applicable `fixed` statement for the same package arrives (the RF-2 mark, reason naming the
  build and advisory).
- **`scripts/vex-accept-applicable.sh`** lists these only with `--include-will-not-fix`.

## What does NOT change

- The auto-accept policy (D9, EDR-GOVERNANCE-01 D15). The `not_affected` path (D15).
- API contracts, event shapes, schemas: none.
- `affected`, `under_investigation` and `fixed` statements still raise nothing.

## Decision record

EDR-VEX-02 amendment D18–D21. No `specs/` deltas; archive with `--skip-specs`.
