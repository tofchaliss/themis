# Tasks — phase3-incident-b

No `specs/` deltas — archive with `openspec archive phase3-incident-b --skip-specs -y`.

## Group 1 — Domain (D2)

- [x] 1.1 `domain/watch.go`: `Watch` (name, creator, identifiers append-only, recorded
  resolution, notify), `ParseWatchIdentifiers` / `WatchIdentifierKind` (CVE-, RHSA-/RHBA-/RHEA-),
  `WatchState` + `WatchStateOf`.
- [x] 1.2 Tests at 100%: parse table, lifecycle, the state table in the fail-safe order.

## Group 2 — App

- [x] 2.1 `app/watch.go`: `WatchService` (create / list / get / add / delete / status), ports
  `WatchStore`, `WatchKnowledge`, `WatchFindings`, `WatchEvidence`; rows per (release, CVE),
  fixes via `selectFixesFor`, names via `ReleaseOwnerResolver`, resolution recorded.
- [x] 2.2 Tests at 100%: lifecycle, the table, empty estate, every failure, row order.

## Group 3 — Knowledge, stores, clients, API, wiring

- [x] 3.1 Knowledge: `ReadService.ByAdvisory` + `AdvisoryLister`, store
  `FaultlinesByAdvisory` (JSONB scan), `GET /faultlines/by-advisory?id=`, wiring; tests.
- [x] 3.2 Governance store: migration 000024 `watches`, `SaveWatch` / `GetWatch` /
  `ListWatches` / `DeleteWatch`; integration test.
- [x] 3.3 Governance clients: knowledge `FaultlineByCVE` / `FaultlinesByAdvisory`, evidence
  `LatestEvidence`; tests at 100%.
- [x] 3.4 OpenAPI `/watches…` + regen, `adapters/http/watch.go` (503 unwired, 400 bad input
  with the rejected tokens, 403 non-admin delete, 404, 500, 503 no Knowledge seam); tests.
- [x] 3.5 Wiring: Watch service always, Knowledge / Registry / Evidence seams when wired.

## Group 4 — GUI, docs

- [x] 4.1 Dashboard `#/watches` (create, list) and `#/watches/{id}` (table, state filter
  chips with counts, CSV export, add identifiers, delete); rail link. `make js-check` green.
- [x] 4.2 CHANGELOG, EDR-INCIDENT-01 step B realization note, BACKLOG INC-1.
- [ ] 4.3 VM: migration governance 24; create a Watch from one RHSA id and two CVE ids of the
  estate; the table lists every project's release with the expected states; CSV export;
  an unseen RHSA shows `unknown`.
