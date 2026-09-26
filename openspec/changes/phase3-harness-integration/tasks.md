# Tasks — phase3-harness-integration

Source of truth: `docs/engineering/decisions/EDR-HARNESS-01.md`.

## Group 1 — Domain and application (D1–D6) — implemented 2026-09-26
- [x] 1.1 `domain/harness.go`: Commission (+ Finding ops, premise, withdrawal), HarnessExecution
      (Validate, DerivedTrust, Corresponds), NewHarnessProposal, thin events; tests.
- [x] 1.2 `app/harness.go`: Commission, WithdrawCommission, RaiseHarnessProposal (+ Business
      Verification via `vouchesRef`); event constants; tests through the fake repo.

## Group 2 — Persistence and API (D1, D5) — implemented 2026-09-26
- [x] 2.1 Migration `000014_harness_commissions` (+ down); `store/harness.go` load/save;
      proposal `commission_id` + `harness_evidence`; schema_ref mapping for the two events.
- [x] 2.2 `api/governance.openapi.yaml`: commission paths, `CommissionRequest/Response/View`,
      `WithdrawCommissionRequest`, `HarnessExecutionEvidence`, additive view fields; regenerated.
- [x] 2.3 `http/harness.go` + handler routing; problem-status mapping.
- [ ] 2.4 Integration test (`-tags=integration`, embedded Postgres): commission and evidence
      round-trip through `Store` — **pending: run `make test-integration` on a host with the
      embedded-Postgres binary cached** (not run in this session).
- [ ] 2.5 Contract test: the two new event types have a pinned `schema_ref`
      (`TestIntegrationContractV1_GovernanceEvents`) — same run as 2.4.

## Group 3 — Adapter, CLI, walls (D8, D9) — implemented 2026-09-26
- [x] 3.1 `adapters/harness/intake.go`: Resolve (D-T-1..6 + five-link D-W-5), Evidence,
      witnessing-constitution table with `l8-delegates-tool-less`.
- [x] 3.2 Fixture `testdata/fixtures/1df0e28548a4/` with provenance; tests: table guard,
      positive resolve, refusals, historical branch.
- [x] 3.3 `cmd/themis-intake`.
- [x] 3.4 `.golangci.yml` adapter rule; `tests/architecture/harness_test.go`.

## Group 4 — Dependency and gate — OPEN
- [ ] 4.1 `go.mod`: `require github.com/tofchaliss/themis-ai-runtime/src/harness v0.0.0-<pseudo>`
      pinned to the published runtime commit — **after the runtime repository is pushed** (until
      then the repository builds only inside a `go.work` including `../themis-ai-runtime/src/harness`).
- [ ] 4.2 `make check` green on a host with the runtime pin resolvable.
