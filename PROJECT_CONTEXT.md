# Themis — Project Context

Themis is an open-source Go backend security intelligence platform. It ingests SBOM and VEX
documents, correlates vulnerabilities, applies VEX overlay semantics, watches for newly
disclosed CVEs, and delivers notifications. Standalone binary backed by PostgreSQL.

---

## Current Status

**Phase 1 — nearly complete.** 199 of 208 tasks done. Group 16 (OSV hardening, image
registration API, coverage cleanup) is in progress. See `project-backlog.md` for what comes
next.

| Phase | Status | Scope |
| ----- | ------ | ----- |
| Phase 1 | In progress (199/208) | Go REST API, PostgreSQL, 8 capabilities — see `openspec/changes/themis-phase-1/` |
| Phase 2 | Not started | AI enrichment, EPSS/KEV, upstream VEX feeds, VEX export — see `project-backlog.md` |
| Phase 3 | Not started | Rate limiting, observability, cosign, CI/CD ingestion, Docker, Redis, Web UI, RBAC/OIDC — see `project-backlog.md` |

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
| L1 / L2 / L3 | The three data layers (see below) |
| InProcessQueue | Phase 1 goroutine-pool implementation of the `JobQueue` domain interface; swappable to Redis in Phase 3 via the same interface |
| StubVerifier | Phase 1 implementation of `SignatureVerifier`; records trust status without cryptographic verification; replaced by CosignVerifier in Phase 2 |
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

## Three-Layer Data Model

```text
  LAYER 1 — IMMUTABLE SOFTWARE INVENTORY TRUTH
  ─────────────────────────────────────────────
  Tables: products, product_versions, artifacts, images, sbom_documents,
          components, component_versions, dependency_relationships,
          vulnerabilities, component_vulnerabilities
  Rule:   Append-only. Never mutated. Never deleted.
          Content-addressed by SHA-256 digest.

  LAYER 2 — MUTABLE VULNERABILITY INTELLIGENCE
  ─────────────────────────────────────────────
  Tables: vex_documents, vex_assertions
  Rule:   Each document is individually immutable (signed, hashed).
          The collection evolves as new VEX revisions arrive.

  LAYER 3 — TEMPORAL EXPLOITABILITY CONTEXT
  ──────────────────────────────────────────
  Tables: intelligence_signals, runtime_exposures, remediation_actions
  Rule:   TTL-based expiry. No inherent provenance.
          NOW (Phase 1): populated by VEX overlay computation only.
          Phase 2: EPSS/KEV sync adds scored signals.
          Phase 3: AI signals.

  CONVERGENCE
  ───────────
  Table: risk_context
  Score (Phase 1): f(raw_severity, vex_effective_state)
    CRITICAL→90, HIGH→70, MEDIUM→40, LOW→10, NONE→0
    SUPPRESSED/FALSE_POSITIVE/ACCEPTED_RISK → ×0.1
    CONFIRMED → ×1.2 (capped at 100)
    RESOLVED → 0
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

13 migrations applied, managed by `golang-migrate`:

| Migration | Content |
| --------- | ------- |
| 000001 | L1: products, product_versions, artifacts, images |
| 000002 | L1: sbom_documents (raw_document JSONB, trust_status, is_latest) |
| 000003 | L1: components, component_versions, dependency_relationships |
| 000004 | L1: vulnerabilities, component_vulnerabilities |
| 000005 | L2: vex_documents, vex_assertions |
| 000006 | L2: intelligence_signals, runtime_exposures, remediation_actions |
| 000007 | L3: risk_context (convergence table) |
| 000008 | Operational: api_keys, notification_rules, cve_watch_findings, audit_log, ingestion_jobs |
| 000009 | Indexes: purl, component_vuln, risk_context, cve_id, sbom dedup (unique) |
| 000010 | risk_context enrichment columns |
| 000011 | triage_history (append-only) |
| 000012 | system_state (last_success timestamps) |
| 000013 | vulnerability package index for OSV/NVD matching |

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
| `AGENTS.md` | AI agent workflow: context sources, how-to-work, scope guardrail |
| `verification.md` | Pre-answer quality checklist (C/S/O rows) |
| `docs/acceptance-criteria.md` | 15 acceptance criteria tested in `tests/acceptance/criteria_test.go` |
| `docs/archive/proposal-initial.md` | Original proposal with 9 ADRs — historical reference |
| `openspec/changes/themis-phase-1/design.md` | 17 design decisions (canonical ADR source) |
| `openspec/changes/themis-phase-1/tasks.md` | Implementation task checklist with 6-gate progress |
| `openspec/changes/themis-phase-1/specs/*/spec.md` | Per-capability requirements and scenarios |
| `tests/acceptance/criteria_test.go` | 15 acceptance criteria test coverage mapping |
