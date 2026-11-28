# Tasks — phase3-image-rebuild

No `specs/` deltas — archive with `openspec archive phase3-image-rebuild --skip-specs -y`.
Every step waits for the owner's go and lands as its own PR.

## Group 0 — Record

- [x] 0.1 EDR-REBUILD-01 merged (PROPOSED, D1 to D46); backlog item `COMM-REBUILD-POLICY-1`.
- [x] 0.2 Owner choices 1 to 4 and 6 to 10 answered; choice 5 (connector repository) is asked
  again at R5.

## Group 1 — R1 installation policy (owner go 2026-11-27)

- [x] 1.1 Domain: `RebuildPolicy` with the seven fields of D2, defaults, validity, mode order and
  `LowestRebuildMode` (D17), `EvaluateRebuild` with `counted_because` (D34). 100% coverage.
- [x] 1.2 App: `RebuildPolicyService` (read, change with a named actor, history). 100% coverage.
- [x] 1.3 Store + migration 28 (up / down): policy in force, version counter, history in one
  transaction; integration test.
- [x] 1.4 API: `GET` / `PUT /rebuild-policy`, `GET /rebuild-policy/history`; admin to change;
  a field left out is refused; wiring; tests.
- [x] 1.5 `make check` and `make vet-tags` green.
- [x] 1.6 VM check PASSED 2026-11-28: defaults at version 0, two changes, a refused change
  (field left out, 400), history newest first. A read-only key was not tried on the VM; the
  handler tests cover it. Result in the EDR, "Step R1 as built".

## Group 2 — R1a Product and Release overrides

- [ ] 2.1 Waits for the owner's go.

## Later groups

- [ ] R2 to R6 as in the EDR's order of work, each on the owner's go.
