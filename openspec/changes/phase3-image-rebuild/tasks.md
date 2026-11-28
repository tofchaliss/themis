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
- [x] 3.5 VM check PASSED 2026-11-28 (second run, after 3.6): no tag, `rebuild:ask` and
  `rebuild:auto` on the Release, `rebuild:off` on its Product, tags removed; the judgement of a
  real Release (596 open occurrences, 92 counted, skip counts add up). The first run found the
  defect of 3.6. Result in the EDR, "Step R2 part 1 as built".
- [x] 3.6 Fix from the VM check: the Registry client reads each level's own tags from the tag
  reads, and refuses an answer with no `tags` field (the single-entity views do not carry
  tags; backlog `RG-VIEW-TAGS-1`).

## Group 4 — R2 part 2: triggers, decision record, events (same owner go)

- [x] 4.0 `KN-BEHIND-MODULE-1` settled for the judgement (owner decision 2026-11-28: do not
  count, show as own group): Knowledge answers `fix: other_stream`, Governance never targets it
  under `fix_required` and lists it in `other_stream`. No migration.
- [x] 4.0a VM check of 4.0: on the checked Release the 92 counted entries split into counted
  and `other_stream` (expected about 48 and 44). PASS 2026-11-28: 48 and 44, groups add up to
  596 (EDR "VM check of this change").
- [ ] 4.0b Sample the `other_stream` fix answers by hand: Knowledge gives 379 of 563 on the
  checked Release. Read 20 across packages and confirm each has no reachable bound (backlog
  `KN-OTHER-STREAM-SAMPLE-1`).
  2026-11-28: 20 of 39 packages read, all right (shape b, one Perl module stream). The other
  19 packages are still to read.
- [x] 4.1 Settle the open points of "Step R2 part 1 as built" that touch the event contract:
  the event keeps the list `fixed_versions`; `fix_source` stays `knowledge_verdict` (EDR "Step
  R2 part 2 as built").
- [x] 4.2 Trigger queue `rebuild_triggers`, written in the same transaction as the
  `release_evaluated` note (cause `new_sbom`) and the `fix_available` note; a worker that
  judges off the inbox transaction, every 30 seconds.
- [x] 4.3 Decision record `rebuild_decisions` with the frozen facts (D27, D29); migration 30,
  reversible. Read `GET /releases/{id}/rebuild-decisions`.
- [x] 4.4 Events `governance.rebuild_requested.v1` and `governance.rebuild_recommended.v1`
  with frozen schemas and contract tests; Communication's consumer ignores event types it does
  not know (its `default` case), confirmed in the code.
- [x] 4.5 VM check: migration 30 applies, a forced trigger is judged, a tagged Release gives a
  decision and one event, an untagged one gives `none` with the reason, nothing is sent out.
  PASS 2026-11-28 (EDR "VM check of part 2").
- [ ] 4.6 See one trigger written by a real event on the VM (a new SBOM or a real
  `fix_available`), and its outcome on the decisions read (backlog `GOV-REBUILD-TRIGGER-LIVE-1`).

## Group 5 — R2a build profile (owner go 2026-11-28, all three parts)

- [x] 5.1 Registry domain and app: the profile checks (JSON object, 16 KiB, 5 levels, no key
  named like a secret), records with revision, actor and digest, removal as a record, and the
  resolved profile of a Release (own, else the Project's, never merged).
- [x] 5.2 Registry store and API: migration 6 `registry_build_profiles`, reversible; `GET`,
  `PUT`, `DELETE` on Project and Release, and `GET /releases/{id}/build-profile/resolved`.
- [x] 5.3 Governance: the worker reads the resolved profile when a judgement would ask for
  something; "no profile, no request"; `recommend_reason`, `build` and `build_profile` on the
  decision, the two events and the decisions read; schemas and contract tests updated.
- [x] 5.4 GUI: the build profile card on the Estate page of the current GUI, with the
  no-secrets rule on the form.
- [x] 5.5 Gates: unit tests, `make vet-tags`, `make lint`, `make clean-arch`, `make arch-test`,
  Registry and Governance integration tests on embedded Postgres.
- [x] 5.6 VM check: Registry migration 6 applies; a Project profile is saved and read back; a
  profile with a secret-like key is refused; a forced trigger on a tagged Release gives a
  decision with `build`; with the profile removed the decision says `no_build_profile`.
  PASS 2026-11-28 (EDR "VM check of R2a").
- [x] 5.6a The same card in the React GUI (`/next/`), which is the GUI in daily use; #280 had
  it in the old GUI only. Component tests, `npm run check`, bundle rebuilt.
- [ ] 5.7 Look at the build profile card in the React GUI on the VM (backlog
  `GUI-BUILD-PROFILE-CHECK-1`).

## Later groups

- [ ] R3 to R6 as in the EDR's order of work, each on the owner's go.
