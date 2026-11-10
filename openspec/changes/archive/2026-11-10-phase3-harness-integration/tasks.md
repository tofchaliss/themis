# Tasks — phase3-harness-integration

Source of truth: `docs/engineering/decisions/EDR-HARNESS-01.md`.

## Group 1 — Domain and application (D1–D6) — implemented 2026-09-26
- [x] 1.1 `domain/harness.go`: Commission (+ Finding ops, premise, withdrawal), HarnessExecution
      (Validate, DerivedTrust, Corresponds), NewHarnessProposal, thin events; tests.
- [x] 1.2 `app/harness.go`: Commission, WithdrawCommission, RaiseHarnessProposal (+ Business
      Verification via `vouchesRef`); event constants; tests through the fake repo.

## Group 2 — Persistence and API (D1, D5) — implemented 2026-09-26, verified 2026-10-06
- [x] 2.1 Migration `000014_harness_commissions` (+ down); `store/harness.go` load/save;
      proposal `commission_id` + `harness_evidence`; schema_ref mapping for the two events.
- [x] 2.2 `api/governance.openapi.yaml`: commission paths, `CommissionRequest/Response/View`,
      `WithdrawCommissionRequest`, `HarnessExecutionEvidence`, additive view fields; regenerated.
- [x] 2.3 `http/harness.go` + handler routing; problem-status mapping.
- [x] 2.4 Integration test (`-tags=integration`, embedded Postgres): commission and evidence
      round-trip through `Store` — **run 2026-10-06, `TestHarnessCommissionAndEvidenceRoundTrip`
      PASSES.** 000014's up/down reversibility is covered by the existing `TestMigrationDownUp`,
      which takes the whole stack down and back up.
- [x] 2.5 Contract test: the two new event types have a pinned `schema_ref`
      (`TestIntegrationContractV1_GovernanceEvents`) — **PASSES, and needs no build tag**: the
      contract test is untagged, so this was green from the first run.

## Group 3 — Adapter, CLI, walls (D8, D9) — implemented 2026-09-26, walls corrected 2026-10-06
- [x] 3.1 `adapters/harness/intake.go`: Resolve (D-T-1..6 + five-link D-W-5), Evidence,
      witnessing-constitution table with `l8-delegates-tool-less`.
- [x] 3.2 Fixture `testdata/fixtures/1df0e28548a4/` with provenance; tests: table guard,
      positive resolve, refusals, historical branch.
- [x] 3.3 `cmd/themis-intake`.
- [x] 3.4 `.golangci.yml` adapter rule; `tests/architecture/harness_test.go`.
- [x] 3.5 **Correct the wall to what it can enforce (2026-10-06).** The second architecture test
      named a reachability wall and asserted nothing — its inner loop body was `_ = ex`. Measured:
      `verification/seam` → `orchestration` → `skills` → `tools`, so `themis-intake` links fifteen
      runtime packages and calls none of them. Replaced with assertions that are true and bite
      (each mutation-checked): `TestIntakeCLIRuntimeReachIsPinned` pins that reach so it cannot
      grow unnoticed, and `TestNoThemisBinaryButTheIntakeCLILinksTheRuntime` holds every other
      binary — Governance's own service and the frozen monolith included — at zero. EDR D8 and the
      package doc now state the scope honestly; the honest-limits section records the reach.
- [x] 3.6 **Register the adapter in `scripts/check-coverage.sh` (2026-10-06).** It was unregistered,
      so the gate skipped it silently — full-repo mode iterates the registered lists only. Added
      the tuple guards and the pre-replay record refusals as tests (81.0% → 83.9%) and registered
      it at the 80% tier with the reason written in the script. Closing to the 90% adapter tier is
      `HARNESS-COV-1`.

## Group 4 — Dependency and gate — CLOSED 2026-10-06
- [x] 4.1 `go.mod`: `require github.com/tofchaliss/themis-ai-runtime/src/harness
      v0.0.0-20260926130325-331d326a4172` — the runtime is published and the pin **resolves from
      `proxy.golang.org` into a cold module cache** (verified 2026-10-06), so `go.work` is a
      developer convenience, not a build requirement.
- [x] 4.2 `make check-ci` green with the pin resolvable — **`GOWORK=off make check-ci` exit 0**
      (2026-10-06): build · vet-tags · test-greenfield · lint · js-check · clean-arch · arch-test ·
      coverage-greenfield · deadcode. `GOWORK=off` is what makes this the real test: `go.work` is
      excluded via `.git/info/exclude` and never reaches CI, so CI builds against the pin alone.
