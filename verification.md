# Verification Checklist

Use this checklist **before a final answer**, before marking work complete, or before opening a PR.
Answer every question that applies to your change. If you cannot point to a test, command, or spec
that verifies the claim, the work is not done.

---

## Before you answer

1. Read the relevant OpenSpec spec:
   - Phase 1: `openspec/changes/archive/2026-06-09-themis-phase-1/specs/<capability>/spec.md`
   - Phase 2a: `openspec/changes/themis-phase-2a/specs/<capability>/spec.md`
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
| C6 | **How are acceptance criteria covered?** | AC-1..15 (Phase 1); AC-16..24 (Phase 2a) — each maps to ≥1 integration/E2E test | `go test -tags=integration ./tests/acceptance/...`; `docs/acceptance-criteria.md` |
| C7 | **How is API shape correctness verified?** | Handlers match OpenAPI | `api/openapi.yaml`; `internal/adapter/api/handlers_*_test.go` |
| C8 | **How is idempotent SBOM ingestion verified?** | Same `(image_digest, checksum)` returns existing scan | `TestE2E_DuplicateSBOMIdempotency`; `sbom-ingestion` spec |
| C9 | **How is the Phase 2a composite risk score formula verified?** | Property test agrees with independent oracle implementation for all valid inputs | `go test ./tests/acceptance/... -run TestCompositeScoreOracleProperty` |
| C10 | **How is Layer 1 sync-before-202 verified?** | Integration test: POST SBOM → `202 Accepted` → immediate query shows non-null `deterministic_level` on every finding | `TestE2E_Layer1SynchronousBeforeAccepted` |
| C11 | **How is soft-deleted SBOM data isolation verified?** | 7-path matrix: status counts, SBOM list, product SBOM list, blast-radius, VEX export, top-components, findings all exclude deleted data | `TestAC22_SoftDeleteIsolation` (integration); negative test `TestSoftDelete_StoreFilterNotCallerFilter` |
| C12 | **How is PURL mismatch always-logged verified?** | Log capture test: simulate all-four-phases-fail → assert structured INFO log with `sbom_purl`, `vex_purl`, `cve_id` fields present | `TestVEXFeed_PURLMismatchAlwaysLogged` |
| C13 | **How is the Alpine OSV fixed-version boundary verified?** | Unit test: installed version == fixed version → `not_affected` (fixed is exclusive in `[introduced, fixed)`) | `TestPhase4_AlpineNotInRange_FixedVersion` |
| C14 | **How is ReEnrichJob idempotency verified?** | Run the same ReEnrichJob twice with identical signal data → `risk_context` row unchanged on second run; no duplicate rows inserted | `TestReEnrichJob_Idempotent` |

**Pass:** All applicable C-rows answered with a green command or passing test.
Task-group work passes gates in the active phase's `tasks.md` for that group.

---

## Severity

Ask these questions before claiming vulnerability severity, risk score, or triage behaviour is correct.

| # | Question | How it is verified | Command / source |
| - | -------- | ------------------ | ---------------- |
| S1 | **How is raw severity verified?** | Stored on immutable `component_vulnerabilities`; copied to `risk_context.raw_severity`; never changed by VEX or triage | `intelligence-enrichment/spec.md` (raw preserved scenarios); `TestEnrichmentVEXOverlayIntegrationPostgres` |
| S2 | **How is effective state verified separately from severity?** | VEX/triage change `risk_context.effective_state` only | `TestE2E_VEXSuppressionPreservesFinding`; `TestE2E_VEXRevokeResurface` |
| S3 | **How is the Phase 1 risk score formula verified?** | `f(raw_severity, effective_state)` — no EPSS/KEV/AI | `internal/usecase/enrichment/score.go`; `score_test.go`; `score_property_test.go` |
| S4 | **How are severity thresholds verified for notifications?** | Routing rules filter on `raw_severity` | `notification-service/spec.md`; `internal/adapter/notify/routing_test.go` |
| S5 | **How are scan severity counts verified in the API?** | `GET /api/v1/scans/{id}` groups `vulnerability_counts` by severity | `sbom-ingestion/spec.md`; catalog handler tests |
| S6 | **How is triage severity semantics verified?** | `false_positive`, `accepted_risk`, `in_triage` update `effective_state` and audit trail | `cve-triage/spec.md`; `TestTriageFlowIntegrationPostgres` |
| S7 | **How is the Phase 2a composite formula verified end-to-end?** | Property test (all valid inputs → score ∈ [0,100]); unit table covering every branch (EPSS/KEV/blast/suppress/resolve/cap) | `score_phase2a_test.go`; `TestCompositeScoreOracleProperty`; `TestCompositeScoreBranches` |
| S8 | **How is `deterministic_level=Critical → risk_score=100` enforced?** | Property test: for any valid EPSS/KEV/blast input, if Layer 1 fires Critical the score is always 100 | `TestDeterministicCriticalAlwaysMax` |
| S9 | **How is the vendor VEX authority (backport) principle verified?** | Integration test: Alpine/RPM package with version < upstream fix + vendor `not_affected` → `effective_state=NOT_AFFECTED`; upstream CVE version range not consulted | `TestVendorVEXAuthority_BackportRPM`; `TestVendorVEXAuthority_BackportApk` |
| S10 | **How is suppression always-reduces property verified?** | Property test: suppressed.risk_score < unsuppressed.risk_score for identical CVSS + signals | `TestSuppressionIsMonotonicallyDecreasing` |
| S11 | **How are Layer 1 rule boundaries verified?** | Table-driven unit tests for every rule (exact boundary values: CVSS=9.0, EPSS=0.5, all signal combos; first-rule-wins ordering) | `TestLayer1Rules_AllBranches`; `TestLayer1Rules_BoundaryValues` |
| S12 | **How is blast-radius Customer deduplication verified?** | Unit test: 3 Deployments owned by the same Customer → blast_radius_score=1.0 (not 1.2); score is monotone as unique Customer count increases | `TestBlastRadius_SharedCustomerDedup`; `TestBlastRadius_Monotone` |

**Reference formula (Phase 1):**

```text
Base: critical=90, high=70, medium=40, low=10
Modifier: suppressed/false_positive/accepted_risk → ×0.1; confirmed → ×1.2 (cap 100); resolved → 0; detected → base
```

**Reference formula (Phase 2a) — BREAKING change from Phase 1:**

```text
base      = f(raw_severity, effective_state)           [Phase 1 formula above]
layer1    = if deterministic_level=Critical → 100 else base
epss_adj  = base × (1 + epss_score × 0.3)             [+0% to +30%; 0 when NULL]
kev_adj   = if kev_listed → +15 else 0
blast_adj = base × blast_radius_score                   [multiplier 1.0–2.0×]
final     = min(100, layer1 + epss_adj + kev_adj + blast_adj)

ai_adj term added in Phase 2b (absent in 2a).
Layer 1 Critical override: deterministic_level=Critical → final=100 regardless.
```

**Pass:** Severity claims cite S-rows; score changes include unit + property tests;
VEX/triage changes prove raw severity unchanged.

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
| O9 | **How is EPSS/KEV sync observability verified?** | Prometheus counters for sync cycles, stale flag, ReEnrichJob batches; `signals_stale` field in `/status` response | `themis_epsskev_sync_total{feed,status}`; `themis_epsskev_stale`; `themis_reenrichjob_batches_total` |
| O10 | **How is PURL mismatch rate observable?** | Per-feed counter incremented whenever four-phase matching exhausts all phases without a match | `themis_vexfeed_purl_mismatch_total{feed}`; INFO log with `sbom_purl`+`vex_purl`+`cve_id` |
| O11 | **How is blast-radius score distribution observable?** | Histogram of `blast_radius_score` values written to `risk_context` at enrichment time | `themis_blast_radius_score` histogram; `go test ./internal/infrastructure/metrics/... -run TestBlastRadiusMetric` |
| O12 | **How is log-level debug mode verified?** | `THEMIS_LOG_LEVEL=debug` emits per-PURL normalisation attempts and Layer 1 rule firings; `info` level emits only sync summaries | Manual smoke: `THEMIS_LOG_LEVEL=debug ./bin/themis`; unit test: `TestLogLevel_DebugEmitsPURLDetail` |
| O13 | **How is vendor VEX feed sync observability verified?** | Per-feed counters for new assertions, updated assertions, parse errors, and sync duration | `themis_vexfeed_sync_total{feed,status}`; `themis_vexfeed_assertions_total{feed,match_type}` |
| O14 | **How is SBOM soft-delete auditable?** | Every deletion writes an `audit_log` row (api_key_id, timestamp, action=`SBOM_DELETED`, sbom_id); query confirms entry present | `TestO14_SBOMDeleteAuditLog`; `SELECT * FROM audit_log WHERE action='SBOM_DELETED'` |

**Expected metric names (non-exhaustive):**

Phase 1: `themis_ingestion_jobs_total`, `themis_job_duration_seconds`, `themis_queue_depth`,
`themis_active_workers`, `themis_notifications_total`, `themis_cve_watch_cycles_total`,
`themis_cve_watch_duration_seconds`, `themis_cve_watch_new_findings_total`.

Phase 2a additions: `themis_epsskev_sync_total`, `themis_epsskev_stale`,
`themis_reenrichjob_batches_total`, `themis_vexfeed_sync_total`,
`themis_vexfeed_assertions_total`, `themis_vexfeed_purl_mismatch_total`,
`themis_blast_radius_score` (histogram), `themis_layer1_rules_fired_total`.

**Pass:** O-rows answered for any change touching HTTP, pipeline, watch, notify, trust, or Phase 2a sync paths.

---

## Feed Resilience

Ask these questions before claiming external signal feeds are production-safe.

| # | Question | How it is verified | Expected behaviour |
| - | -------- | ------------------ | ------------------ |
| FR1 | **EPSS endpoint unreachable** | Mock HTTP 500 for 3 attempts | WARNING logged per attempt; previous `intelligence_signals` data unchanged; ingestion unblocked |
| FR2 | **EPSS CSV truncated (< 50% of prior row count)** | Return 100-row CSV when 200k rows expected | Sync aborted; previous data retained; WARNING with row-count comparison logged |
| FR3 | **KEV JSON is malformed (CDN HTML error page)** | Return `text/html` instead of JSON | Parse error logged at ERROR; previous KEV data retained; no crash |
| FR4 | **ExploitDB CSV returns 0 rows** | Return empty body | Existing `exploit_records` unchanged; WARNING logged; no rows deleted |
| FR5 | **Vendor VEX feed returns HTTP 429** | Return 429 on first attempt, 200 on second | Exponential backoff; retry succeeds; normal advisory ingestion proceeds |
| FR6 | **Vendor CSAF advisory missing required field** | Return advisory with `productStatus` absent | Advisory skipped; ERROR logged with advisory ID; remaining advisories in same sync still processed |
| FR7 | **EPSS score value outside [0.0, 1.0]** | Row with `epss=-0.1` or `epss=1.5` | Row rejected; error logged; valid rows in same CSV still upserted |
| FR8 | **Stale signal flag set after 25h** | Mock time advance past TTL | `intelligence_signals.stale=true`; `GET /api/v1/status` includes `"signals_stale":true` |

**Pass:** FR-rows answered for any change touching `adapter/epsskev/`, `adapter/exploitdb/`, or `adapter/vexfeed/`.

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

**Phase 2a smoke — signal feeds, status, and graph:**

Note: EPSS/KEV/ExploitDB/vendor VEX sync runs on daily schedulers at startup — no admin trigger endpoint yet. Wait for the first poll cycle or run integration tests locally.

```sh
# System status (live SQL; top-N components; signals_stale when EPSS/KEV overdue)
curl -s "http://localhost:8080/api/v1/status?top=5" \
  -H "X-API-Key: $THEMIS_API_KEY" | jq .

# SBOM inventory
curl -s "http://localhost:8080/api/v1/sboms?limit=10" \
  -H "X-API-Key: $THEMIS_API_KEY" | jq .

# Register graph entities
curl -s -X POST http://localhost:8080/api/v1/customers \
  -H "X-API-Key: $THEMIS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"Platform Team","contact_email":"platform@example.com"}' | jq .

# Export VEX for a product version
curl -s "http://localhost:8080/api/v1/products/{id}/versions/{v}/vex?format=cyclonedx" \
  -H "X-API-Key: $THEMIS_API_KEY" | jq '.vulnerabilities | length'

# VEX coverage aggregate
curl -s "http://localhost:8080/api/v1/products/{id}/versions/{v}/vex-coverage" \
  -H "X-API-Key: $THEMIS_API_KEY" | jq .

# Error envelope example (missing API key → MISSING_API_KEY)
curl -s "http://localhost:8080/api/v1/status" | jq .

# Metrics (Group 30 wires remaining Phase 2a counters)
curl -s http://localhost:8080/metrics | grep themis_
```

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
