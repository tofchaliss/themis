# Evidence Context — Verification Baseline & Test Learnings

**Captured:** 2026-07-16 · **Context:** `phase3-evidence` (M6), the realized greenfield exemplar.

This is a **proven-behavior baseline** for the completed Evidence context: what was run, what passed, and —
more usefully — **what each test proves and the pattern to copy** when building Knowledge → Governance →
Communication (which mirror this template). Re-run the commands below to detect regressions before extending
the context or starting the next one. Source decisions: `docs/engineering/decisions/EDR-EVIDENCE-01.md`
(D1–D9); reusable build patterns: the six `implementation-blueprint/` docs.

## Environment

- **Go** 1.25 · **macOS** (darwin), Homebrew Go · **no Docker**.
- Integration + e2e use **`fergusstrange/embedded-postgres` V16** (real Postgres 16.9 in-process on
  `:15555`). This is the zero-setup Mac path; set `EVIDENCE_E2E_DSN` to point at an external DB instead.

## How to reproduce

```sh
# Greenfield unit + integration tests with coverage (Evidence + kernel):
go test -tags=integration -p 1 ./internal/evidence/... ./internal/kernel/...

# Architecture test (inward-only rings + no cross-context imports):
make arch-test

# End-to-end smoke test (embedded Postgres, full REST flow, sample SBOM):
make e2e-evidence
#   own SBOM:      EVIDENCE_E2E_SBOM=/path/to/your.sbom.json make e2e-evidence
#   SPDX input:    EVIDENCE_E2E_FORMAT=spdx make e2e-evidence
#   external DB:   EVIDENCE_E2E_DSN=postgres://... make e2e-evidence

# Full canonical gate (whole repo, incl. frozen legacy tree — slow):
make check
```

## Test-case pass rate (current change)

**100% — 69/69 pass, 0 fail, 0 skip.** Scoped to the code new in `phase3-evidence`: 64 unit/integration +
architecture cases (53 top-level + 11 sub-tests) and **5 e2e scenarios**. Counted from fresh (`-count=1`)
verbose runs.

## Results — greenfield packages (all green)

Run: `go test -tags=integration -p 1 ./internal/evidence/... ./internal/kernel/...` → **all `ok`**.

| Package | Coverage | Tier | Verdict |
| --- | --- | --- | --- |
| `internal/kernel/value` | 100.0% | 100% (domain) | ✅ |
| `internal/evidence/domain` | 100.0% | 100% (domain) | ✅ |
| `internal/evidence/app` | 100.0% | 100% (domain) | ✅ |
| `internal/evidence/adapters/parser` | 100.0% | 100% (domain) | ✅ |
| `internal/evidence/adapters/trust` | 100.0% | 100% (domain) | ✅ |
| `internal/evidence/adapters/subjectref` | 100.0% | 100% (domain) | ✅ |
| `internal/evidence/adapters/http` | 95.7% | ≥90% (infra) | ✅ |
| `internal/evidence/adapters/store` | 84.5% | ≥80% (special) | ✅ |

Coverage tiers are defined in `scripts/check-coverage.sh`. `store` sits in a documented 80% tier: its
behavior is proven by integration tests (below); the remaining uncovered lines are DB-error branches that
need pgxpool-fault injection (see Known gaps). Generated code (`adapters/http/gen/`) and the composition
package (`adapters/wiring/`) are excluded from the coverage calc — `wiring` is exercised by the e2e test.

## Gate results

| Gate | Command | Result |
| --- | --- | --- |
| Build | `go build ./...` | ✅ exit 0 |
| Architecture | `make arch-test` | ✅ inward-only rings + no cross-context imports hold |
| Coverage (greenfield) | per-package above | ✅ every package clears its tier |
| Full canonical gate | `make check` | ✅ **exit 0** — all coverage thresholds satisfied, whole repo |

`make check` = build · test · lint · clean-arch · arch-test · coverage · deadcode over the **whole** repo
(greenfield + the frozen v0.3.x legacy tree). It exited **0**. `deadcode` is informational (always exit 0);
it reported 3 unreachable funcs in the legacy `usecase/enrichment` `NoOpMetricsRecorder` — legacy tree, not
a gate failure. The full-repo coverage gate checked these greenfield packages, all green:
`kernel/value` · `evidence/domain` · `evidence/app` · `evidence/adapters/parser` ·
`evidence/adapters/trust` · `evidence/adapters/subjectref` (100%) and `evidence/adapters/http` (95.7% ≥ 90%).

**Gate-wiring gap found (worth fixing).** `evidence/adapters/store` is **not** listed in
`scripts/check-coverage.sh` (`domain_pkgs` / `infra_pkgs`), so its 80% floor — the special-case in
`threshold_for` — is **only enforced by the per-group `make coverage-pkg` gate, never by `make check`**. Its
84.5% was verified directly here, but the canonical whole-repo gate silently skips it. Add
`evidence/adapters/store` to the coverage lists (fold in with the store fault-injection follow-up).

## End-to-end result — 5-scenario suite

Run: `make e2e-evidence` → **PASS (≈10s, all 5 scenarios)**. Real embedded Postgres 16.9, started **once**
for the whole suite via `TestMain` (each scenario uses its own Release / distinct bytes, so they share the
DB without colliding; outbox assertions are scoped per Evidence id).

| Scenario | What it drives | Result |
| --- | --- | --- |
| `TestEvidenceEndToEnd` (CycloneDX happy path) | register → facts → inventory(2) → list → idempotent replay → exactly-one event | ✅ |
| `TestEvidenceSPDX` | register an **SPDX** SBOM → parses into the canonical inventory (2 components) | ✅ |
| `TestEvidenceUnknownReleaseRejected` | unregistered Release → **422** `unknown subject release` (rejected pre-persist) | ✅ |
| `TestEvidenceUnsupportedFormatRejected` | `format=trivy` (a producer, not a standard) → **422** `unsupported SBOM format`, `supported=[cyclonedx spdx]` | ✅ |
| `TestEvidenceConcurrentDuplicate` | 8 simultaneous identical uploads → **1 create, one id, exactly 1 event** | ✅ |

The happy-path flow proven through real HTTP + real Postgres:

1. `POST /api/v1/evidence` (new) → **201** + stable Evidence id.
2. `GET /evidence/{id}` → facts: `subject_release_id`, `trust_status = accepted`.
3. `GET /evidence/{id}/inventory` → **2 components** parsed into the canonical inventory.
4. `GET /evidence?release=…` → list contains the id.
5. `POST` the same bytes again → **200** + **same id** (idempotent replay).
6. `SELECT count(*) FROM evidence_outbox WHERE evidence_id=…` → **exactly 1** (event fired once, not on replay).

The rejection scenarios prove the **error-UX** path (Problem envelope, helpful supported-formats list) and the
concurrent scenario proves the **fingerprint-idempotent Save + exactly-once outbox** under real HTTP
concurrency — not just the sequential replay. Add SPDX/rejection/concurrency scenarios like these to every
context's e2e suite.

## What each test proves — the pattern to copy

The next contexts (Knowledge, Governance, Communication) mirror this exact test shape. Copy it.

- **`domain` (unit, 100%)** — aggregate **immutability + construction invariants**: no setters; `NewEvidence`
  rejects empty id / invalid kind / zero fingerprint / empty subject / bad trust / zero time; an SBOM must
  carry a non-empty inventory; `Inventory` returns **defensive copies**. → Every context: test the aggregate
  root's invariants and immutability purely, with no I/O.
- **`adapters/parser` (unit, 100%)** — the **inbound ACL**: CycloneDX + SPDX → one canonical inventory;
  **standards-only**, unsupported formats get a helpful typed rejection (`*UnsupportedFormatError`). → Every
  context with an ACL (Knowledge feed ACLs, Communication serializers): golden-file tests + explicit
  unsupported-input rejection.
- **`adapters/trust` (unit, 100%)** — the **admission gate**: SHA-256 fingerprint + expected-checksum match +
  well-formed-JSON + provenance capture, returning an accept/reject verdict.
- **`adapters/store` (integration, 84.5%)** — the **persistence + outbox contract**, proven against real
  Postgres: fingerprint-idempotent `Save` (`ON CONFLICT (fingerprint) DO NOTHING`) writing record **+** outbox
  note in **one transaction**; concurrent duplicate uploads resolve to **one row + one event**; `Relay`
  delivers un-sent notes with **exactly-once-eventually** semantics (fail-then-retry); migration **up/down**
  reversibility. → Every context: prove idempotency, the transactional outbox, and concurrency on a real DB,
  not a mock.
- **`app` (unit, 100%)** — the **use-case orchestration** over ports (fakes, no DB): `Register` runs
  validate-subject → trust → parse → build → save(+outbox); **rejects unknown subject**; **idempotent replay**
  returns the existing id. → Every context: drive app services through port fakes; assert the orchestration
  and error paths, not the adapters.
- **`adapters/http` (unit, 95.7%)** — the handler implements the **generated `ServerInterface`** (spec-first
  oapi-codegen) and renders the **Problem error envelope**; request/response mapping is covered by table
  tests against a fake service.
- **`tests/architecture` (arch-test)** — the **boundary guarantee**: rings point inward only and **no
  cross-context imports** exist. Add each new context to the `boundedContexts` slice. This is what keeps the
  contexts genuinely isolated — it must stay green as contexts are added.
- **`tests/e2e` (e2e, black-box)** — the **whole context through real HTTP + real Postgres via the shared
  `wiring` package** (identical wiring to `cmd/evidence`), including idempotent replay and the exactly-one
  outbox event. → Every context ships one `make e2e-<ctx>` like this; run it each dev cycle.

## Known gaps / follow-ups (not regressions)

- **`store` DB-error branches uncovered (→ 84.5%).** Lifting to ≥90% needs an **injectable pgxpool
  interface** for fault injection (the legacy `pgQueryPool` / `errRow` pattern). The _behavior_ is already
  proven by integration tests; only the error-return plumbing is uncovered. Tracked in
  `project_phase3_evidence_impl` memory.
- **`SubjectRef` uses a stub validator.** `adapters/subjectref` is an allow-set stub until
  `phase3-shared-kernel` supplies the registry `ReleaseExists`. The e2e seeds the allow-set with the test
  release id. Swapping in the real registry adapter is the first integration after the kernel lands.

## Regression baseline

Treat the tables above as the **known-good baseline**. Before extending Evidence or starting the next
context, re-run the four reproduce commands; any package dropping below its tier, any arch-test failure, or
an e2e break is a regression to fix before proceeding.
