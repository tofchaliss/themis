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

## Group 2 — R1a Product and Release overrides (owner go 2026-11-28)

- [x] 2.1 Domain: `ResolveRebuildPolicy` (nearest wins whole, mode ceiling of D17). App: set,
  read, remove, history, list, in force for a Release. 100% coverage.
- [x] 2.2 Store + migration 29 (up / down): three scope kinds, removal kept in the history,
  version counted per scope across removals; integration test with concurrent changes.
- [x] 2.3 API: `/rebuild-policies`, `/products/{id}/rebuild-policy`, `/releases/{id}/rebuild-policy`
  (+ `/history`, `/in-force`); admin or the Product's key to change; tests; `make check` parts
  and the dashboard's generated API types green.
- [x] 2.4 VM check PASSED 2026-11-28: a Product policy and a Release policy, the in-force read
  for two releases at each stage, the list, both removals, the history. Result in the EDR,
  "Step R1a as built".
- [ ] 2.5 GUI page for the policies (`GUI-REBUILD-POLICY-1`), on the owner's go.

## Group 3 — R2 part 1: the judgement as a read (owner go for R2 2026-11-28)

- [x] 3.1 Knowledge: `FixStandingOf` (known / none / unknown from the recorded verdict),
  `GET /releases/{id}/fix-verdicts`, store read of the live match rows; unit and integration
  tests. No migration.
- [x] 3.2 Governance domain: `ResolveRebuildTag` (D4), `EffectiveRebuildMode` (D17),
  `RebuildOutcome`, skip counts on `EvaluateRebuild`. 100% coverage.
- [x] 3.3 Governance app and adapters: Registry tag read per level, Knowledge fix-verdict
  client, `RebuildFacts` store read, `RebuildEvaluationService`; the in-force read carries the
  tag and the effective mode. No migration.
- [x] 3.4 API: `GET /releases/{id}/rebuild-evaluation`; `tag`, `effective_mode`,
  `effective_mode_set_by` on the in-force read; tests; lint, vet-tags, clean-arch, arch-test
  and the dashboard's generated API types green.
- [ ] 3.5 VM check: a Release with no tag, with `rebuild:ask`, with `rebuild:off` on its
  Product; the judgement of a real Release (counted components, skip counts).

## Group 4 — R2 part 2: triggers, decision record, events (same owner go)

- [ ] 4.1 Settle the six open points of "Step R2 part 1 as built" that touch the event
  contract (one fixed version or a list, `fix_source`).
- [ ] 4.2 Trigger queue written with the outbox notes of `release_evaluated` (cause `new_sbom`)
  and `fix_available`; a worker that evaluates off the inbox transaction.
- [ ] 4.3 Decision record with the frozen facts (D27, D29); migration.
- [ ] 4.4 Events `governance.rebuild_requested.v1` and `governance.rebuild_recommended.v1`;
  confirm Communication ignores event types it does not know.
- [ ] 4.5 VM check.

## Later groups

- [ ] R2a to R6 as in the EDR's order of work, each on the owner's go.
