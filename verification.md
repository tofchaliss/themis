# Verification Checklist

Use this checklist **before a final answer**, before marking work complete, or before opening a PR.
Answer every question that applies to your change. If you cannot point to a test, command, or spec
that verifies the claim, the work is not done.

---

## Before you answer

1. Read the relevant OpenSpec spec: `openspec/changes/themis-phase-1/specs/<capability>/spec.md`
2. Run structural gates for touched packages (see [Correctness](#correctness))
3. State which checklist sections you verified and which you skipped (with reason)

---

## Correctness

Ask these questions before claiming the system or change is correct.

| # | Question | How it is verified | Command / source |
| - | -------- | ------------------ | ---------------- |
| C1 | **How is correctness verified structurally?** | Lint, import direction, coverage, dead code | `make check` |
| C2 | **How is a clean rebuild verified?** | Full repo builds from scratch after changes | `make verify-build` |
| C3 | **How are domain invariants verified?** | Raw findings never deleted/mutated; VEX only changes `risk_context.effective_state` | `openspec/.../intelligence-enrichment/spec.md`; integration tests in `internal/adapter/store/`, `internal/usecase/enrichment/` |
| C4 | **How is Clean Architecture verified?** | Imports point inward only | `make clean-arch` |
| C5 | **How is the ingestion pipeline verified end-to-end?** | Upload → job COMPLETED → findings → risk_context → audit_log | `go test -tags=integration ./internal/infrastructure/http/...` (E2E tests); Group 7/8 gates in `tasks.md` |
| C6 | **How are the 15 acceptance criteria covered?** | Each criterion maps to at least one integration/E2E test name | `go test -tags=integration ./tests/acceptance/... -run TestAcceptanceCriteriaCoverage`; `proposal-initial.md` § Acceptance Criteria |
| C7 | **How is API shape correctness verified?** | Handlers match OpenAPI | `api/openapi.yaml`; `internal/adapter/api/handlers_*_test.go` |
| C8 | **How is idempotent SBOM ingestion verified?** | Same `(image_digest, checksum)` returns existing scan | `TestE2E_DuplicateSBOMIdempotency`; `sbom-ingestion` spec |

**Pass:** All applicable C-rows answered with a green command or passing test. Task-group work also passes gates in `openspec/changes/themis-phase-1/tasks.md` for that group.

---

## Severity

Ask these questions before claiming vulnerability severity, risk score, or triage behaviour is correct.

| # | Question | How it is verified | Command / source |
| - | -------- | ------------------ | ---------------- |
| S1 | **How is raw severity verified?** | Stored on immutable `component_vulnerabilities`; copied to `risk_context.raw_severity`; never changed by VEX or triage | `intelligence-enrichment/spec.md` (raw preserved scenarios); `TestEnrichmentVEXOverlayIntegrationPostgres` |
| S2 | **How is effective state verified separately from severity?** | VEX/triage change `risk_context.effective_state` only | `TestE2E_VEXSuppressionPreservesFinding`; `TestE2E_VEXRevokeResurface` |
| S3 | **How is the Phase 1 risk score formula verified?** | `f(raw_severity, effective_state)` only — no EPSS/KEV/AI in Phase 1 | `internal/usecase/enrichment/score.go`; `score_test.go`; `score_property_test.go` |
| S4 | **How are severity thresholds verified for notifications?** | Routing rules filter on `raw_severity` | `notification-service/spec.md`; `internal/adapter/notify/routing_test.go` |
| S5 | **How are scan severity counts verified in the API?** | `GET /api/v1/scans/{id}` groups `vulnerability_counts` by severity | `sbom-ingestion/spec.md`; catalog handler tests |
| S6 | **How is triage severity semantics verified?** | `false_positive`, `accepted_risk`, `in_triage` update `effective_state` and audit trail | `cve-triage/spec.md`; `TestTriageFlowIntegrationPostgres` |

**Reference formula (Phase 1):**

```text
Base: critical=90, high=70, medium=40, low=10
Modifier: suppressed/false_positive/accepted_risk → ×0.1; confirmed → ×1.2 (cap 100); resolved → 0; detected → base
```

**Pass:** Severity claims cite S-rows; score changes include unit + property tests; VEX/triage changes prove raw severity unchanged.

---

## Observability

Ask these questions before claiming the system is observable, debuggable, or auditable.

| # | Question | How it is verified | Command / source |
| - | -------- | ------------------ | ---------------- |
| O1 | **How is health verified?** | Liveness and readiness endpoints | `curl http://localhost:8080/healthz`; `curl http://localhost:8080/readyz` |
| O2 | **How are Prometheus metrics verified?** | `/metrics` exposes ingestion, queue, watch, notification counters | `go test ./internal/infrastructure/metrics/...`; scrape after ingestion: `curl -s localhost:8080/metrics \| grep themis_` |
| O3 | **How is ingestion pipeline tracing verified?** | OTel spans per stage (injected via context, not in use cases) | `internal/infrastructure/metrics/tracing.go`; Group 14 gates in `tasks.md` |
| O4 | **How is structured logging verified?** | JSON logs with `timestamp`, `level`, `component`, `request_id` | `internal/infrastructure/http/logger.go`; Phase 1 is `info` only — configurable log level is Phase 2 (`runtime-observability`) |
| O5 | **How is the audit trail verified?** | Trust rejections, triage, enrichment transitions write `audit_log` | `artifact-trust/spec.md`; `TestGateIntegrationPostgres`; enrichment integration tests |
| O6 | **How is ingestion status verified without debug logs?** | Lifecycle API exposes `status`, `stage_detail`, `scan_id` | `GET /api/v1/ingestions/{id}`; `ingestion_jobs` table in Postgres |
| O7 | **How is CVE watch observability verified?** | Watch cycle metrics and logs | `cve-watch/spec.md`; `themis_cve_watch_*` metrics in `metrics_test.go` |
| O8 | **How is notification delivery observability verified?** | Per-channel success/failure metrics | `notification-service/spec.md`; `themis_notifications_total` |

**Expected metric names (non-exhaustive):** `themis_ingestion_jobs_total`, `themis_job_duration_seconds`, `themis_queue_depth`, `themis_active_workers`, `themis_notifications_total`, `themis_cve_watch_cycles_total`, `themis_cve_watch_duration_seconds`, `themis_cve_watch_new_findings_total`.

**Pass:** O-rows answered for any change touching HTTP, pipeline, watch, notify, or trust paths.

---

## Manual smoke (optional, local)

When verifying a running binary (not CI-only):

```sh
export THEMIS_DATABASE_DSN="postgres://..."
make build && ./bin/themis

curl -s http://localhost:8080/healthz
curl -s http://localhost:8080/readyz | jq .
curl -s http://localhost:8080/metrics | grep themis_
```

Full CycloneDX upload walkthrough: [README.md § Testing](README.md#testing).

---

## Final answer template

Before your final response to the user, include a short verification block:

```text
## Verification
- Correctness: C1, C2, … (commands run / tests passed)
- Severity: S1, S3, … (or N/A — no severity path touched)
- Observability: O2, O6, … (or N/A)
- Skipped: … (reason)
```

If any required row fails, do not present the change as complete.
