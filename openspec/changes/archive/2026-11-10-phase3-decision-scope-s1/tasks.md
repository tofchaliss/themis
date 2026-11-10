# Tasks — phase3-decision-scope-s1

No `specs/` deltas — archive with `openspec archive phase3-decision-scope-s1 --skip-specs -y`.

## Group 1 — Domain (D1, D3, D8)

- [x] 1.1 `domain/scope.go`: `DecisionScope` + `ParseDecisionScope`, `Covers`,
  `PropagationSource`, `ScopedProposalID`, `ScopedRationale`, `Position.Scope/PropagatedFrom/
  IsScopedSource`; `AcceptanceTerms.Scope/PropagatedFrom` validated in `checkTerms`.
- [x] 1.2 Tests at 100%: parse table, covers table, accept with scope and propagation.

## Group 2 — App (D2, D4, D5, D6)

- [x] 2.1 `app/scope.go`: `ScopePropagation` (`Targets`, `Apply`, `Sweep`, `ForRelease`,
  `RunEvery`), `ScopedPositions` port, `FindingService.ApplyScopedPosition`.
- [x] 2.2 Worker hook `ReleaseEvaluationWorker.WithScopePropagation`, before roll-forward; a
  failure defers the row.
- [x] 2.3 Tests at 100%: targets table; sweep applies in the person's name with the terms
  copied; stale version and propagated Positions never act; failures leave the row pending;
  later-born Finding gets the standing decision; conflict applies nothing; cancelled contexts.

## Group 3 — Store, API, wiring, docs

- [x] 3.1 Migration 000023 up/down; `loadPositions`/`savePositions` round trip;
  `PendingScopedPositions` / `MarkScopeApplied`; integration test.
- [x] 3.2 OpenAPI: `DecisionRequest.scope`, `PositionView.scope/propagated_from_*`,
  `GET /findings/{id}/scope-targets`; handler + tests (400 bad scope, 404 unknown Finding,
  500 Registry outage, 503 no seam).
- [x] 3.3 Wiring under the Registry seam; `THEMIS_SCOPE_SWEEP_INTERVAL` on `cmd/governance`.
- [x] 3.4 `node.env.example`, CHANGELOG, EDR-SYNC-01 status + realization note, BACKLOG SYNC-1.
- [x] 3.5 VM (2026-11-03): migration governance 23; decided with `scope=product` on project
  A; the one undecided sibling (third project, artifact level) showed the Position within a
  sweep, same person, `propagated_from_*` set; the sibling decided the day before kept its own
  Position; preview count 1 matched. Later-upload case not yet exercised.
- [x] 3.6 Names beside ids (owner ask on the VM round): `ReleaseOwnerResolver` (registry client
  `ReleaseOwners`, three hops), `ScopeTarget.ProductName/ProjectName/Version`, preview fields
  `product_name`/`project_name`/`version`, rationale "from <project> <version>".

## Group 4 — S2, the GUI (D7; owner "work on last 3 items", 2026-11-03)

- [x] 4.1 `cmd/dashboard/static/app.js`: Scope picker in the Decide form (default release),
  preview from `GET /findings/{id}/scope-targets` with names and counts, 503 and errors shown
  as such; `scope` on the accept body; toast names the scope.
- [x] 4.2 Current position chips "decided for <scope>" / "applied from another release";
  proposal chips "applied by scope" / "roll-forward". `make js-check` green.
- 4.3 → moved to `phase3-pending-tests` (section 2) on 2026-11-10: the GUI picker (#226) still
  needs its VM check; the scope API passed its VM round on 2026-11-03.
