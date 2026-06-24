# Themis — Project Context

Themis is an open-source Go backend security intelligence platform. It ingests SBOM and VEX
documents, correlates vulnerabilities, applies VEX overlay semantics, watches for newly
disclosed CVEs, and delivers notifications. Standalone binary backed by PostgreSQL.

---

## Current Status

**Phase 1 — shipped** as `v0.1.0` (archived). **Phase 2a — shipped** as `v0.2.0` (archived);
`v0.2.1` maintenance release archived. See `project-backlog.md` for deferred items.

**`v0.3.0` — shipped (2026-06-24).** Tag `v0.3.0` bundles the `themis-core-model` restructure
(`sbom_documents` → `sboms` + `scan_reports`; merged `artifacts`/`images`; `versions.project_id`;
`risk_context` + judgment tables re-keyed on `(artifact_id, component_purl, cve_id)`; schema-skew
guard) **plus** the Layer-0 Correctness & Observability refactor (below). Breaking schema — no
in-place upgrade from a pre-`v0.3.0` database. All gates green; merged to `themis-phase-2` and
tagged. See `openspec/changes/themis-core-model/`.

**Layer-0 Correctness & Observability refactor (CR-1…CR-10) — shipped in `v0.3.0`.** The
correlation/feeder/observability core was rebuilt on the core-model base: one version engine
(`CompareVersionsEco`), one `Correlator` over a `CorrelationSource` port with finding provenance
and distro-authoritative merge, distro/RHSA feeds re-layered from the VEX overlay into correlation
(severity + fixed version), an NVD-by-CVE CVSS backfill, a `domain.Logger` port, and a
`feed_health`/`degraded_feeds[]` surface. This closes defects D-CVSS-1, D-FEED-1, D-NVD-1, D-LOG-1.
Remaining (post-release follow-ups): operational G1–G8 verification on real SBOMs, and the
user-defined feed registry. See `project-backlog.md` §"Layer-0 Correctness & Observability Refactor".

| Phase | Status | Scope |
| ----- | ------ | ----- |
| Phase 1 | Shipped (`v0.1.0`) | Go REST API, PostgreSQL, 8 capabilities — see `openspec/changes/archive/` |
| Phase 2a | Shipped (`v0.2.0` / `v0.2.1`) | EPSS/KEV, ExploitDB, vendor VEX, graph, VEX export, status/SBOM APIs, error UX |
| core-model + Layer-0 refactor | **Shipped (`v0.3.0`, 2026-06-24)** | Schema restructure + Durable-Enrichment Identity Contract; CR-1…CR-10 (version engine, single correlator + provenance, feed re-layering, CVSS backfill, logging port, feed health) — closes D-CVSS-1/D-FEED-1/D-NVD-1/D-LOG-1 |
| Phase 2b | Ready to start (unblocked) — targets `v0.4.0` | AI workers, pgvector KB, GHSA — additive on the `v0.3.0` identity base (zero core-model ALTERs) |
| Phase 2c | Planned — targets `v0.5.0` | AI-assisted VEX auto-apply — blocked on 2b |
| Phase 3 | Not started | Rate limiting, Docker, Web UI, Redis, RBAC/OIDC — see `project-backlog.md` |

---

## Core Concepts

| Term | Meaning |
| ---- | ------- |
| SBOM | Software Bill of Materials — CycloneDX or SPDX format document listing all components in an artifact |
| VEX | Vulnerability Exploitability eXchange — overlay document that contextualises raw findings without deleting them |
| PURL | Package URL — canonical component identity used for CVE matching and deduplication |
| risk_context | Convergence table — computed effective state combining all three data layers; sole source of truth for a finding's current status |
| effective_state | Live status of a finding: DETECTED, SUPPRESSED, CONFIRMED, IN_TRIAGE, ACCEPTED_RISK, FALSE_POSITIVE, RESOLVED |
| VEX overlay | VEX assertions change only `risk_context.effective_state`; raw findings in `component_vulnerabilities` are never deleted or modified |
| L0 / L1a / L1b / L1c / L2 / L3 | The five data layers (Phase 2+ model; see below). Phase 1 used a three-layer model (L1/L2/L3) now superseded. |
| InProcessQueue | Phase 1 goroutine-pool implementation of the `JobQueue` domain interface; swappable to Redis in Phase 3 via the same interface |
| StubVerifier | Phase 1 implementation of `SignatureVerifier`; records trust status without cryptographic verification; replaced by CosignVerifier in Phase 3 |
| AIWorkerRuntime | Phase 2 port interface for the AI enrichment backend; implemented by `adapter/ai/` (Ollama/CyberPal-2.0) |
| SecurityKnowledgeGraph | Phase 2 graph: CVE ↕ CWE ↕ Package ↕ Product ↕ Microservice ↕ Deployment ↕ Customer; blast-radius traversal |
| CanonicalSBOM | Internal model that all SBOM formats normalise into; only `adapter/parser/` knows about CycloneDX/SPDX/Trivy structs |

---

## Permanent Invariants (never violate)

1. **VEX overlay, never delete** — VEX changes `risk_context.effective_state` only; rows in
   `component_vulnerabilities` are preserved forever. If VEX is revoked, the finding resurfaces.

2. **Transport ≠ domain** — CycloneDX/SPDX/Trivy structs exist only in `internal/adapter/parser/`;
   all other packages see only `CanonicalSBOM` and domain types.

3. **Integrity chain** — VEX references SBOM checksum; SBOM references image digest; Themis
   records this chain. Cryptographic verification of signatures is Phase 2 (StubVerifier today).

4. **Deduplication** — same `(image_digest, checksum_sha256)` on SBOM upload is idempotent;
   different checksum on same image = new scan with `is_latest=true`. `Idempotency-Key` header
   on all mutating endpoints.

5. **L4 triage generates L3** — every human triage decision auto-creates a `vex_document` with
   `source=themis_generated`, which then auto-applies on future ingestions of the same
   `(component_purl, cve_id)` pair.

---

## Data Model

Phase 1 used a three-layer model (L1 inventory / L2 VEX intelligence / L3 temporal
signals). Phase 2 introduces a revised five-layer model that accommodates the AI
enrichment pipeline, the Security Knowledge Graph, and semantic memory.

```text
  L0  RAW IMMUTABLE INVENTORY                          (v0.3.0 core-model)
  ────────────────────────────────────────────────────────────────
  Tables: products, projects, versions, artifacts,
          sboms, scan_reports,
          components, component_versions, dependency_relationships,
          vulnerabilities, component_vulnerabilities, vex_documents,
          vex_assertions
  Rule:   Append-only. Never mutated. Never deleted.
          Content-addressed by SHA-256 digest.
  Core-model split (themis-core-model, v0.3.0):
    • sboms        = uploaded composition, keyed (artifact_id, sbom_checksum).
    • scan_reports = one correlation run's findings at a point in time
                     (N per artifact; "latest" = ORDER BY scanned_at DESC —
                     no is_latest / supersedes_id).
    • artifacts    merges the old artifacts+images; image_digest is globally UNIQUE.
    • versions     replaces product_versions, parented by a project
                     (versions.project_id NOT NULL; default project auto-created).
    • component_vulnerabilities carries denormalized version-qualified
      component_purl + cve_id (the per-scan raw finding).
    • Durable Layer-2/3 judgment tables (risk_context, triage_history,
      remediation_actions, intelligence_signals, runtime_exposures) key on the
      stable identity (artifact_id, component_purl, cve_id) — triage survives rescans.

  L1a ASSET & DEPENDENCY GRAPH                        (Phase 2+)
  ────────────────────────────────────────────────────────────────
  Tables: asset_graph_nodes, asset_graph_edges
  Nodes:  Component → Microservice → Deployment → Customer
  Phase 2: SQL graph tables.
  Phase 3: Apache AGE (Cypher queries).

  L1b SECURITY KNOWLEDGE GRAPH                        (Phase 2+)
  ────────────────────────────────────────────────────────────────
  Blast-radius graph: CVE ↕ CWE ↕ Package ↕ Product
                      ↕ Microservice ↕ Deployment ↕ Customer
  Populated by the Vulnerability Intelligence Collector (L0 → L1b).
  Enables: "which customers are running the package affected by CVE-X?"

  L1c SEMANTIC MEMORY                                 (Phase 2+)
  ────────────────────────────────────────────────────────────────
  Table: embeddings (entity_type, entity_id, vector, model, created_at)
  Extension: pgvector. Model: CyberPal-2.0 embed or nomic-embed.
  Embeds: CVE descriptions, VEX justifications, AI summaries,
          triage decisions. Powers RAG retrieval for AI workers.

  L2  AI ENRICHMENT                                   (Phase 2+)
  ────────────────────────────────────────────────────────────────
  Tables: ai_summaries, ai_cwe_mappings, ai_exploitability,
          ai_vex_recommendations, ai_remediation_advice
  Rule:   Immutable per (worker_id, input_hash). Re-run = new row.
          Confidence < 0.5 → advisory only; not used in scoring.

  L3  HUMAN VALIDATION
  ────────────────────────────────────────────────────────────────
  Tables: triage_history (Phase 1), approvals (Phase 2+),
          vex_overrides (Phase 2+), audit_log (Phase 1)
  Rule:   Append-only. Every human decision is a permanent record.

  CONVERGENCE → risk_context
  ────────────────────────────────────────────────────────────────
  Phase 1 score: f(raw_severity, vex_effective_state)
    CRITICAL→90, HIGH→70, MEDIUM→40, LOW→10, NONE→0
    SUPPRESSED/FALSE_POSITIVE/ACCEPTED_RISK → ×0.1
    CONFIRMED → ×1.2 (capped at 100)
    RESOLVED → 0

  Phase 2 score: h(severity, vex_state, epss_score, kev_flag,
                   ai_exploitability, ai_reachability_confidence)
```

---

## Clean Architecture

All code follows Robert C. Martin's Clean Architecture. The Dependency Rule is absolute:
**source code dependencies can only point inward**.

```text
  cmd/themis/main.go           DI root only — wires everything, imported by nothing
  internal/infrastructure/     Layer 4: pgx, chi, config, queue, metrics, CLI
  internal/adapter/            Layer 3: parsers, store, API handlers, notify, trust, nvd, osv
  internal/usecase/            Layer 2: ingestion, enrichment, triage, watch
  internal/domain/             Layer 1: pure types + port interfaces (stdlib only)

  IMPORT RULE
  domain/         → stdlib only
  usecase/        → domain/ only
  adapter/        → domain/, usecase/
  infrastructure/ → all inner layers
  cmd/            → infrastructure/ only
```

Enforced by `go-cleanarch` and `depguard` in `.golangci.yml`. `make clean-arch` fails on
any violation. CI enforces this on every push.

---

## Technology Stack

All versions reflect what is in `go.mod` as built.

| Concern | Library | Version |
| ------- | ------- | ------- |
| Language | Go | 1.25.0 |
| Database | PostgreSQL + pgx | pgx/v5 v5.10.0 |
| Migrations | golang-migrate | v4.19.1 |
| HTTP router | go-chi/chi | v5.3.0 |
| OpenAPI stubs | oapi-codegen | v2.4.1 |
| OpenAPI validation | getkin/kin-openapi | v0.127.0 |
| JSON schema | santhosh-tekuri/jsonschema | v6.0.2 |
| Logging | go.uber.org/zap | v1.28.0 |
| Metrics | prometheus/client_golang | v1.23.2 |
| Tracing | go.opentelemetry.io/otel | v1.44.0 |
| Config | gopkg.in/yaml.v3 | v3.0.1 |
| Crypto | golang.org/x/crypto | v0.46.0 |
| UUID | google/uuid | v1.6.0 |
| Clean arch lint | roblaszczak/go-cleanarch | v1.2.1 |
| Dead code | golang.org/x/tools/cmd/deadcode | via tools.go |
| Property testing | pgregory.net/rapid | v1.3.0 |
| Embedded Postgres | fergusstrange/embedded-postgres | v1.34.0 (test only) |

---

## Code Structure

```text
themis/
├── cmd/themis/main.go               DI root
│
├── internal/
│   ├── domain/                      Layer 1 — pure types + port interfaces
│   │   ├── sbom.go                  CanonicalSBOM, CanonicalComponent, CanonicalDependencyEdge
│   │   ├── vulnerability.go         Vulnerability, CVE types
│   │   ├── vex.go                   VEXAssertion, EffectiveState
│   │   ├── product.go               Product, ProductVersion, Image
│   │   ├── risk.go                  RiskContext, risk score formula
│   │   ├── trust.go                 TrustResult, TrustStatus, trust policy types
│   │   ├── ingestion.go             IngestionJob, lifecycle states
│   │   ├── triage.go                TriageDecision, triage history types
│   │   ├── watch.go                 CVEWatchFinding, watch types
│   │   ├── catalog.go               Component catalog types
│   │   ├── notification.go          NotificationEvent, routing rule types
│   │   ├── enrichment.go            EnrichmentResult types
│   │   ├── job.go                   Job, JobType, JobQueue interface
│   │   ├── ports.go                 All repository + service interfaces
│   │   ├── tracing.go               OTel span key types (no OTel import)
│   │   └── version_match.go         PURL version range matching logic
│   │
│   ├── usecase/                     Layer 2 — application business rules
│   │   ├── ingestion/               Trust gate → parse → store → correlate → enrich → notify
│   │   ├── enrichment/              VEX overlay, effective state machine, risk score
│   │   ├── triage/                  Human triage decisions, VEX generation, history
│   │   └── watch/                   CVE feed orchestration, catalog matching, new findings
│   │
│   ├── adapter/                     Layer 3 — interface adapters
│   │   ├── parser/                  CycloneDX, SPDX, Trivy → CanonicalSBOM + registry
│   │   ├── store/                   PostgreSQL implementations of all domain repositories
│   │   ├── notify/                  SMTP + Teams delivery, routing rules, digest, retry
│   │   ├── trust/                   StubVerifier, hash, schema validation, policy enforcement
│   │   ├── api/                     HTTP handlers, OpenAPI stubs, auth + HMAC middleware
│   │   ├── nvd/                     NVD API client + rate limiter
│   │   └── osv/                     OSV API client, ecosystem mapping, component fetcher
│   │
│   ├── infrastructure/              Layer 4 — frameworks and drivers
│   │   ├── db/                      pgx connection pool, embedded Postgres (tests)
│   │   ├── queue/                   InProcessQueue, postgres store, backoff, noop
│   │   ├── http/                    chi router, startup, schedulers (watch, triage expiry)
│   │   ├── config/                  YAML + env var loading
│   │   ├── metrics/                 Prometheus registration, OTel setup, middleware
│   │   └── cli/                     Admin CLI (create-key, revoke-key)
│   │
│   └── testutil/                    Shared test data generators (gen.go)
│
├── migrations/                      SQL migration files (000001–000013)
├── api/openapi.yaml                 OpenAPI 3.1 spec (source of truth for handlers)
├── api/oapi-codegen.yaml            Code generation config
├── scripts/check-coverage.sh        Per-package coverage threshold enforcement
└── tests/acceptance/                15 acceptance criteria tests + score oracle
```

---

## Database Migrations

Managed by `golang-migrate`. **v0.3.0 (`themis-core-model`) squashes the prior
000001–000019 chain into a single greenfield baseline** — `000001_v030_baseline` —
which defines the whole schema coherently, plus the `v_latest_findings` view and a
startup schema-skew guard. There is **no in-place upgrade** from a pre-v0.3.0
database: drop and recreate, then `make migrate-up` (see README § Full database reset).

| Migration | Content |
| --------- | ------- |
| 000001_v030_baseline | products, projects, versions, artifacts (merged, unique `image_digest`); sboms + scan_reports; components, component_versions, dependency_relationships; vulnerabilities, component_vulnerabilities (denormalized `component_purl`/`cve_id`); vex_documents (→artifacts), vex_assertions; risk_context PK `(artifact_id, component_purl, cve_id)`; triage_history / remediation_actions / intelligence_signals / runtime_exposures re-keyed on the same identity; operational + Phase 2a tables (asset graph, epss_kev_signals, exploit_records, system_state); indexes; `v_latest_findings` view |

`BinarySchemaVersion = 1`. A database left at the old version (≥2) fails startup
loudly via the schema-shape guard with a "re-initialise your database" message.

---

## Ingestion Pipeline Lifecycle

```text
RECEIVED → VALIDATING → CORRELATING → ENRICHING → COMPLETED → NOTIFIED
                │               │
                ▼               ▼
            REJECTED          FAILED (retryable)
```

Stages: trust gate → parse/normalize → correlate/store findings → VEX overlay /
risk_context → notify. The pipeline is not HTTP — upload, webhook, and future git
ingestion all call the same `IngestionService.IngestSBOM` use case.

---

## API Conventions

- **Versioning:** `/api/v1/` prefix; breaking changes get `/api/v2/`
- **Pagination:** cursor-based on all list endpoints (`?cursor=...&limit=50`)
- **Errors:** RFC 7807 Problem Details `{type, title, status, detail, instance}`
- **Async:** upload and webhook endpoints return `202 Accepted`
- **Idempotency:** `Idempotency-Key` header on all mutating endpoints
- **Auth:** `X-API-Key` header; keys are product-scoped; bcrypt-hashed in DB; admin via CLI
- **Webhook auth:** HMAC-SHA256 `X-Themis-Signature` header

---

## Code Quality Gates

Two separate checks, run in this order after every task group:

### 1. Task-wise gates (scoped to the group's packages)

1. Unit tests — `go test ./internal/<package>/...`
2. Coverage — `make coverage-pkg PKG=<path>` (register new packages in `scripts/check-coverage.sh` first)
3. Dead code — `make deadcode`
4. Integration tests — `go test -tags=integration ./internal/<package>/...`
5. Clean Architecture — `make clean-arch`

**Thresholds:** 100% for `domain/`, `usecase/*/`, `adapter/parser/`, `adapter/trust/`,
`adapter/notify/`; ≥90% for `adapter/store/`, `adapter/api/`, `infrastructure/*/`.

### 2. Full codebase build (always last)

1. `make verify-build` — clean then build entire repo from scratch

---

## Trust Policy Levels (per product)

```text
strict      Require signed SBOM, verified supplier, complete provenance.
            Reject unsigned or unverifiable artifacts.
standard    Accept unsigned (trust_status=unsigned). Require valid schema.
            Log missing provenance as warnings. (Default)
permissive  Accept all valid-schema artifacts. For testing/dev only.
```

Phase 1 + 2: `StubVerifier` records trust status without real cryptographic verification.
Phase 3: `CosignVerifier` replaces StubVerifier via the `SignatureVerifier` interface swap.

---

## Reference Documents

| Document | Contents |
| -------- | -------- |
| `README.md` | Build, run, config, test instructions and getting-started guide |
| `project-backlog.md` | All deferred Phase 2 and Phase 3 items with decision rationale |
| `docs/phase-2a-capabilities.md` | Phase 2a capability boundary and API list |
| `AGENTS.md` | AI agent workflow: context sources, how-to-work, scope guardrail |
| `verification.md` | Pre-answer quality checklist (C/S/O rows) |
| `docs/acceptance-criteria.md` | 15 acceptance criteria tested in `tests/acceptance/criteria_test.go` |
| `docs/archive/proposal-initial.md` | Original proposal with 9 ADRs — historical reference |
| `openspec/changes/themis-phase-1/design.md` | 17 design decisions (canonical ADR source) |
| `openspec/changes/themis-phase-1/tasks.md` | Implementation task checklist with 6-gate progress |
| `openspec/changes/themis-phase-1/specs/*/spec.md` | Per-capability requirements and scenarios |
| `tests/acceptance/criteria_test.go` | 15 acceptance criteria test coverage mapping |
