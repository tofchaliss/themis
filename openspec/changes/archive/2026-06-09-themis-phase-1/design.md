# Themis Phase 1 Design

## Context

Themis is a greenfield Go backend — a security intelligence platform that ingests SBOM and VEX documents, correlates vulnerabilities, applies VEX overlay semantics, watches for newly disclosed CVEs, and delivers notifications. There is no existing system to migrate from.

The platform is designed as a standalone binary backed by PostgreSQL. Phase 1 is API-only (no UI). Phase 2 adds AI enrichment and CI/CD git integration. Phase 3 adds Docker production stack and UI. All architectural decisions in Phase 1 must not obstruct these future phases.

**Key constraints:**

- Open-source distribution — single binary, zero-magic setup
- PostgreSQL as sole data store — no SQLite, no Redis in Phase 1
- Cosign signature verification is a stub in Phase 1 — real sigstore calls in Phase 2
- No AI, no EPSS, no KEV in Phase 1 — intelligence enrichment is VEX overlay only
- Job queue is in-process (goroutine pool) behind an interface — swappable to Redis in Phase 3

---

## Goals / Non-Goals

**Goals:**

- Deliver a working Go REST API that ingests SBOM/VEX documents, correlates CVEs, applies VEX overlay, watches for new CVEs, and sends notifications
- Establish the three-layer data model as the canonical internal representation
- Define a job queue interface that Phase 3 can swap without touching business logic
- Keep the ingestion pipeline as an internal service — not coupled to HTTP handlers — so Phase 2 git ingestion calls the same pipeline
- Produce an OpenAPI specification as a first-class artifact alongside the binary
- All 15 acceptance criteria from proposal-initial.md must be met

**Non-Goals:**

- AI enrichment (Phase 2)
- EPSS / KEV sync (Phase 2)
- Real cosign cryptographic verification — stub only (Phase 2)
- CI pipeline automation / Jenkins shared library (Phase 2)
- Git-driven ingestion / GitHub / GitLab webhooks (Phase 2)
- Web UI / dashboard (Phase 3)
- Docker Compose production stack (Phase 3)
- Redis job queue (Phase 3)
- Full RBAC / OIDC (Phase 3)

---

## Decisions

### Decision 1: Three-Layer Data Separation (ADR-3 + ADR-5)

All data is partitioned into three layers with fundamentally different mutation, trust, and caching characteristics:

```text
  LAYER 1 — IMMUTABLE SOFTWARE INVENTORY TRUTH
  ─────────────────────────────────────────────
  Entities: products, product_versions, artifacts, images, sbom_documents,
            components, component_versions, dependency_relationships,
            vulnerabilities, component_vulnerabilities
  Properties: Append-only. Never mutated. Never deleted. Cryptographically
              verifiable. Content-addressed by SHA-256 digest.

  LAYER 2 — MUTABLE VULNERABILITY INTELLIGENCE
  ─────────────────────────────────────────────
  Entities: vex_documents, vex_assertions
  Properties: Each document is individually immutable (signed, hashed).
              The collection evolves as new VEX revisions arrive or
              assertions are revoked. Event-driven cache invalidation.

  LAYER 3 — TEMPORAL EXPLOITABILITY CONTEXT
  ──────────────────────────────────────────
  Entities: intelligence_signals, runtime_exposures, remediation_actions
  Properties: TTL-based expiry. No inherent provenance. System functional
              with stale data during feed outages.
              Phase 1: populated only by VEX overlay computation.
              Phase 2: EPSS/KEV sync adds scored signals.

  CONVERGENCE: risk_context
  ─────────────────────────
  Computed effective state combining all three layers.
  Single source of truth for "what is the current status of this vulnerability?"
  risk_score in Phase 1 = f(raw_severity, vex_effective_state) only.
```

**Why:** Format standards evolve independently. Tightly coupling internal models to CycloneDX or SPDX schemas creates migration burden. When a new format ships with breaking changes, only the adapter layer changes — core domain, DB schema, API contracts, and enrichment pipelines remain untouched.

---

### Decision 2: Transport/Interchange Decoupling (ADR-1 + ADR-2)

CycloneDX and SPDX are treated as transport formats only. The platform normalizes all ingested documents into an internal canonical model on arrival. Format-specific structs exist only in adapter/parser packages — never imported by core domain.

```text
  CycloneDX document ──▶ CycloneDX adapter ──▶ CanonicalSBOM (internal)
  SPDX document      ──▶ SPDX adapter      ──▶ CanonicalSBOM (internal)
  Trivy JSON output  ──▶ Trivy adapter      ──▶ CanonicalSBOM (internal)

  Core domain only ever sees CanonicalSBOM. Never a CycloneDX struct.
```

**Why:** Adding a new format requires only a new adapter. Zero core changes.

---

### Decision 3: VEX Overlay — Never Delete (ADR-4)

Raw vulnerability findings are immutable evidence. VEX assertions add a contextual layer that changes the *effective state* in `risk_context` — they never suppress or delete the raw finding.

```text
  Raw finding stored:   CVE-2024-1234, component=lodash@4.17.21, severity=HIGH
                        ↑ NEVER changes. NEVER deleted.

  VEX assertion:        status=not_affected, justification=code_not_reachable
                        ↑ ALSO immutable evidence once ingested.

  risk_context:         effective_state=SUPPRESSED
                        raw_severity=HIGH (preserved)
                        vex_status=not_affected (overlaid)
                        ↑ BOTH truths coexist.

  If VEX revoked:       effective_state reverts to DETECTED
                        The raw finding was always there.
```

**Why:** Auditability, compliance, forensics, safe revocation. Required for acceptance criteria 6 and 13.

---

### Decision 4: Job Queue as an Interface (Phase 1 → Phase 3 bridge)

The ingestion pipeline dispatches work units via a `JobQueue` interface. Phase 1 implements it as an in-process goroutine pool. Phase 3 swaps in Redis-backed queue with zero business logic change.

```go
type Job struct {
    ID      string
    Type    JobType  // IngestSBOM, IngestVEX, CorrelateVulns, etc.
    Payload []byte
}

type JobQueue interface {
    Enqueue(ctx context.Context, job Job) error
    Consume(ctx context.Context) (<-chan Job, error)
    Ack(ctx context.Context, jobID string) error
}

// Phase 1: InProcessQueue  — goroutine pool + buffered channels
// Phase 3: RedisQueue       — same interface, Redis streams backend
```

**Why:** Phase 3 requires horizontal scaling (multiple worker processes). Coupling to goroutines now would require a rewrite. The interface costs nothing in Phase 1.

---

### Decision 5: Ingestion Pipeline as Internal Service

HTTP handlers (upload endpoint, webhook endpoint) call a shared `IngestionService` — they are not the pipeline. This allows Phase 2 to add git ingestion without duplicating the pipeline.

```text
  POST /api/v1/sbom/upload  ──▶ IngestionService.IngestSBOM(ctx, artifact)
  POST /api/v1/webhooks/scan ──▶ IngestionService.IngestSBOM(ctx, artifact)
  Phase 2 Git handler       ──▶ IngestionService.IngestSBOM(ctx, artifact)

  IngestionService owns:
    validate → parse → correlate → VEX overlay → risk_context → notify
```

---

### Decision 6: Cosign Verification Stub (Phase 1)

Artifact trust validation includes a `SignatureVerifier` interface. Phase 1 ships a stub implementation that always returns `trust_status=unsigned` when no signature is present and `trust_status=unverified` otherwise, recording the trust status without performing real cryptographic verification.

```go
type SignatureVerifier interface {
    Verify(ctx context.Context, artifact RawArtifact) (TrustResult, error)
}

// Phase 1: StubVerifier    — records trust_status, no real crypto
// Phase 2: CosignVerifier  — real sigstore/cosign network calls
```

**Why:** Real cosign verification requires sigstore network calls and key management that are out of Phase 1 scope. The interface ensures Phase 2 is a drop-in replacement.

---

### Decision 7: Canonical Entity Model (ADR-5)

```text
  LAYER 1 ENTITIES
  ─────────────────────────────────────────────────────────────────
  products              Organizational grouping
  product_versions      Versioned release of a product
  artifacts             Generic artifact (parent of Image)
  images                Container image (digest-identified)
  sbom_documents        Immutable SBOM tied to an artifact
  components            Package identity (PURL)
  component_versions    Specific version of a component
  dependency_relationships  Dep graph edges (direct/transitive)
  vulnerabilities       Known vulnerability (CVE)
  component_vulnerabilities  Component × vulnerability join table

  LAYER 2 ENTITIES
  ─────────────────────────────────────────────────────────────────
  vex_documents         Immutable VEX document with provenance
  vex_assertions        Individual assertion within a VEX doc

  LAYER 3 ENTITIES
  ─────────────────────────────────────────────────────────────────
  intelligence_signals  Generalized signal (Phase 1: VEX-derived only)
  runtime_exposures     Deployment context per artifact
  remediation_actions   Tracked fix with status and assignment

  CONVERGENCE
  ─────────────────────────────────────────────────────────────────
  risk_context          Computed effective state (L1 + L2 + L3)

  OPERATIONAL
  ─────────────────────────────────────────────────────────────────
  notification_rules    Routing rules for notification delivery
  cve_watch_findings    New CVE findings from background jobs
  audit_log             Immutable record of security-sensitive actions
  api_keys              Hashed API keys with product scope
```

---

### Decision 8: Deduplication Strategy (ADR-8)

```text
  SBOM dedup key:  UNIQUE(image_digest, checksum_sha256)
  VEX dedup key:   UNIQUE(sbom_checksum, checksum_sha256)

  Same image + same SBOM content  → DUPLICATE. Return existing. Idempotent.
  Same image + different SBOM     → NEW SCAN. Store. Mark is_latest=true.
  Different image + any SBOM      → NEW INGESTION. Store normally.

  Idempotency-Key header on upload/webhook endpoints prevents duplicate
  processing from CI retries.
```

---

### Decision 9: Integrity Chain (ADR-8)

Every artifact is linked to its source through a verifiable chain:

```text
  image_signature ──verifies──▶ image_digest (SHA-256)
                                     │
  sbom_signature ──verifies──▶  sbom_checksum (SHA-256)
                                     │ sbom references image_digest
                                     │
  vex_signature ──verifies──▶   vex_checksum (SHA-256)
                                     │ vex references sbom_checksum
```

Phase 1 records this chain. Cryptographic verification of signatures is Phase 2.

---

### Decision 10: API Design Conventions

- **Versioning**: `/api/v1/` URL prefix. Breaking changes get `/api/v2/`.
- **Pagination**: Cursor-based on all list endpoints (`?cursor=...&limit=50`)
- **Errors**: RFC 7807 Problem Details — `{type, title, status, detail, instance}`
- **Async**: Upload and webhook endpoints return `202 Accepted` immediately; processing is async via JobQueue
- **Idempotency**: `Idempotency-Key` header on mutating endpoints
- **OpenAPI**: Spec generated from Go annotations alongside the binary. First-class artifact.

---

### Decision 11: Trust Policies

Configurable per product with three levels:

```text
  strict      Require signed SBOM, verified supplier, complete provenance.
              Reject unsigned or unverifiable artifacts.
  standard    Accept unsigned with trust_status=unsigned. Require valid schema.
              Log missing provenance as warnings. (Default)
  permissive  Accept all valid-schema artifacts. For testing/dev only.
```

---

### Decision 12: Authentication — API Keys Only (Phase 1)

- `X-API-Key` header required on all API calls; keys stored hashed (bcrypt) in DB
- Keys are product-scoped; a key for Product A cannot access Product B
- Key management via CLI (`themis admin create-key`); no self-service API
- Webhook signature verification via HMAC-SHA256 (`X-Themis-Signature`)
- Full RBAC with OIDC/OAuth2 is Phase 3

---

### Decision 13: Ingestion Lifecycle States

```text
  RECEIVED → VALIDATING → CORRELATING → ENRICHING → COMPLETED → NOTIFIED
                │               │
                ▼               ▼
            REJECTED          FAILED (retryable)
```

- **RECEIVED**: Payload structurally valid, accepted
- **VALIDATING**: Artifact trust gate — schema, hash, provenance, supplier, stub sig check
- **CORRELATING**: Parse + normalize SBOM, extract components, correlate CVEs, store raw findings
- **ENRICHING**: Apply VEX assertions, compute effective_state, compute risk_score (Phase 1: severity + VEX only)
- **COMPLETED**: risk_context populated, results stored
- **NOTIFIED**: Notification dispatched per routing rules
- **FAILED**: Retryable processing error
- **REJECTED**: Non-retryable — invalid input, schema failure, trust failure

---

### Decision 14: Observability from Day One

- **Metrics**: Prometheus-compatible endpoint (`/metrics`) — ingestion rates, queue depth, job durations, CVE watch execution time, notification delivery counts
- **Tracing**: OpenTelemetry across the full ingestion lifecycle
- **Health**: `/healthz` (liveness) and `/readyz` (readiness — checks DB connectivity, CVE feed reachability)
- **Structured logs**: JSON format with `timestamp`, `level`, `component`, `request_id`, `product`, `project`
- **Audit log**: All triage decisions, config changes, key management, and trust validation results written to `audit_log`

---

### Decision 16: Clean Architecture

Themis SHALL follow Clean Architecture (Robert C. Martin) as the structural principle for all packages. The Dependency Rule is the single most important constraint: **source code dependencies can only point inward**. An inner layer MUST NOT import anything from an outer layer.

#### The Four Layers

```text
  ┌─────────────────────────────────────────────────────────────────────┐
  │  LAYER 4 — INFRASTRUCTURE / FRAMEWORKS & DRIVERS                    │
  │  internal/infrastructure/                                           │
  │  cmd/                                                               │
  │                                                                     │
  │  ┌─────────────────────────────────────────────────────────────┐   │
  │  │  LAYER 3 — INTERFACE ADAPTERS                               │   │
  │  │  internal/adapter/                                          │   │
  │  │                                                             │   │
  │  │  ┌─────────────────────────────────────────────────────┐   │   │
  │  │  │  LAYER 2 — USE CASES                                │   │   │
  │  │  │  internal/usecase/                                  │   │   │
  │  │  │                                                     │   │   │
  │  │  │  ┌─────────────────────────────────────────────┐   │   │   │
  │  │  │  │  LAYER 1 — DOMAIN ENTITIES                  │   │   │   │
  │  │  │  │  internal/domain/                           │   │   │   │
  │  │  │  │  Pure types, domain interfaces, no imports  │   │   │   │
  │  │  │  └─────────────────────────────────────────────┘   │   │   │
  │  │  └─────────────────────────────────────────────────────┘   │   │
  │  └─────────────────────────────────────────────────────────────┘   │
  └─────────────────────────────────────────────────────────────────────┘

  DEPENDENCY RULE: arrows point inward only
  domain/ ← usecase/ ← adapter/ ← infrastructure/ ← cmd/
```

#### Layer Definitions

**Layer 1 — Domain (`internal/domain/`)**

- Pure Go types: `CanonicalSBOM`, `CanonicalComponent`, `RiskContext`, `VEXAssertion`, `Vulnerability`, `Product`, `Image`, `EffectiveState`, `TrustStatus`
- Port interfaces: `SBOMRepository`, `VulnerabilityRepository`, `RiskContextRepository`, `NotificationSender`, `SignatureVerifier`, `JobQueue`
- Zero external imports — only Go standard library
- No framework, no DB driver, no HTTP package, no logger

**Layer 2 — Use Cases (`internal/usecase/`)**

- Application business rules organized by capability:
  - `usecase/ingestion/` — orchestrate trust gate + parse + store + correlate + enrich + notify
  - `usecase/enrichment/` — VEX overlay, effective state machine, risk score computation
  - `usecase/triage/` — human triage decisions, VEX generation from L4, history
  - `usecase/watch/` — CVE feed polling, catalog matching, new finding creation
- Imports: `internal/domain/` only
- Defines use case input/output structs (never HTTP request/response types)
- Zero knowledge of PostgreSQL, HTTP, SMTP, or any framework

**Layer 3 — Interface Adapters (`internal/adapter/`)**

- Translates between use cases and external formats/systems:
  - `adapter/parser/` — CycloneDX, SPDX, Trivy adapters → `domain.CanonicalSBOM`
  - `adapter/store/` — PostgreSQL implementations of `domain.*Repository` interfaces
  - `adapter/notify/` — SMTP and Teams implementations of `domain.NotificationSender`
  - `adapter/trust/` — `StubVerifier` (Phase 1), future `CosignVerifier` (Phase 2)
  - `adapter/api/` — HTTP handlers; translate HTTP request → use case input, use case output → HTTP response
- Imports: `internal/domain/`, `internal/usecase/`
- MUST NOT import `internal/infrastructure/`

**Layer 4 — Infrastructure (`internal/infrastructure/`)**

- Frameworks and drivers — wires everything together:
  - `infrastructure/db/` — `pgx` connection pool, `golang-migrate` runner
  - `infrastructure/queue/` — `InProcessQueue` implementation of `domain.JobQueue`
  - `infrastructure/http/` — `chi` router setup, middleware registration
  - `infrastructure/config/` — YAML + env var config loading
  - `infrastructure/metrics/` — Prometheus registration, OpenTelemetry setup
- Imports: all inner layers (this is the only layer permitted to import everything)
- `cmd/themis/main.go` imports `infrastructure/` to wire the dependency graph (DI root)

#### Directory Layout

```text
themis/
├── cmd/
│   └── themis/
│       └── main.go              ← DI root; wires infra → adapter → usecase → domain
│
└── internal/
    ├── domain/                  ← Layer 1: entities + port interfaces
    │   ├── sbom.go
    │   ├── vulnerability.go
    │   ├── vex.go
    │   ├── product.go
    │   ├── risk.go              (RiskContext, EffectiveState, risk score types)
    │   └── ports.go             (SBOMRepository, JobQueue, NotificationSender, etc.)
    │
    ├── usecase/                 ← Layer 2: application business rules
    │   ├── ingestion/
    │   ├── enrichment/
    │   ├── triage/
    │   └── watch/
    │
    ├── adapter/                 ← Layer 3: interface adapters
    │   ├── parser/              (CycloneDX, SPDX, Trivy)
    │   ├── store/               (PostgreSQL repo implementations)
    │   ├── notify/              (SMTP, Teams)
    │   ├── trust/               (StubVerifier)
    │   └── api/                 (HTTP handlers + OpenAPI)
    │
    └── infrastructure/          ← Layer 4: frameworks & drivers
        ├── db/
        ├── queue/
        ├── http/
        ├── config/
        └── metrics/
```

#### The Dependency Rule — Enforced by Tooling

```text
  ALLOWED IMPORTS                        FORBIDDEN IMPORTS
  ───────────────                        ─────────────────
  domain/     → stdlib only              domain/     → usecase/, adapter/, infrastructure/
  usecase/    → domain/                  usecase/    → adapter/, infrastructure/
  adapter/    → domain/, usecase/        adapter/    → infrastructure/
  infrastructure/ → all inner layers     (no restriction on infrastructure/)
  cmd/        → infrastructure/ only     cmd/        → usecase/, adapter/, domain/ directly
```

Enforced via `go-cleanarch` (github.com/roblaszczak/go-cleanarch) and a `depguard` rule in `.golangci.yml`. CI fails on any import direction violation.

**Why Clean Architecture for Themis:**

- Business logic (use cases) is testable without a database, HTTP server, or any framework — pure Go tests with no infrastructure setup
- Phase 2 and Phase 3 add new adapters (AI client, cosign verifier, Git provider) without touching use cases or domain
- The `JobQueue` interface in `domain/` means Phase 3 can swap `InProcessQueue` for `RedisQueue` by changing only `infrastructure/queue/` — zero use case changes
- Protects the VEX overlay semantics and triage state machine from being polluted by framework concerns

---

### Decision 17: Code Quality Gates — Coverage and Dead Code

Every package in Themis MUST meet coverage and dead code thresholds before a task group is considered complete. These are enforced in CI and locally via `make check`.

#### Coverage targets by package type

```text
  PACKAGE TYPE                         MINIMUM COVERAGE    ENFORCEMENT
  ─────────────────────────────────────────────────────────────────────
  Domain / business logic              100%                Hard fail
    internal/domain/
    internal/usecase/enrichment/
    internal/usecase/triage/
    internal/usecase/ingestion/
    internal/usecase/watch/
    internal/adapter/parser/
    internal/adapter/trust/
    internal/adapter/notify/ (routing + aggregation)

  Infrastructure (DB, HTTP, external)   90%                Hard fail
    internal/adapter/store/
    internal/adapter/api/
    internal/infrastructure/db/
    internal/infrastructure/queue/
    internal/infrastructure/http/

  Generated code (oapi-codegen stubs)  Excluded            N/A
  cmd/main.go entry point              Excluded            N/A
```

Rationale: domain packages contain pure business logic with no external dependencies — 100% is achievable and mandatory. Infrastructure packages have error paths tied to network/DB failures that require mocks or real infrastructure to trigger; 90% is the enforceable floor.

#### Dead code — zero tolerance

The system SHALL have zero unreachable or unused code at ship time. Every exported function, type, and constant MUST have at least one consumer (test or production caller). This is enforced by:

- `golang.org/x/tools/cmd/deadcode` — static reachability analysis from `main()`; flags functions never called — static reachability analysis from `main()`; flags functions never called
- `staticcheck` (already in golangci-lint) — flags unused exports, unreachable statements, redundant code
- `go vet ./...` — standard Go analysis, catches shadowing, unreachable code, and misuse patterns

#### Tooling and enforcement

```makefile
# Makefile targets
coverage:              ## Run tests with coverage; fail below threshold
    go test -coverprofile=coverage.out -covermode=atomic ./...
    go tool cover -func=coverage.out | tee coverage.txt
    @scripts/check-coverage.sh coverage.txt  # fails if any pkg below threshold

deadcode:              ## Detect unreachable functions
    deadcode -test ./...

check:                 ## Run all quality gates: build + lint + coverage + deadcode
    $(MAKE) build
    $(MAKE) lint
    $(MAKE) coverage
    $(MAKE) deadcode
```

`scripts/check-coverage.sh` reads `coverage.txt` and fails with a non-zero exit code if any non-excluded package reports below its threshold.

#### What "no loose ends" means in practice

- Every function defined in a non-excluded package MUST be called by either a test or production code
- Every interface method MUST have at least one concrete implementation exercised by tests
- Every error path MUST be covered — use `errors.New` stubs or interface mocks to trigger them
- Stub implementations (e.g., `StubVerifier`) MUST be tested even though they are temporary
- No `TODO:`, `FIXME:`, or commented-out code blocks may remain at task group completion

---

### Decision 15: Database Migrations

- Tool: `golang-migrate` — SQL migration files versioned in the repo
- Forward-only in production. Destructive changes require two-phase approach.
- Themis refuses to start if DB schema version ahead of binary version.
- Every migration tested with up + down paths in CI.

---

## Risks / Trade-offs

**Stub cosign in Phase 1 means trust chain is incomplete**
→ Documented limitation. `trust_status` field is present and queryable; Phase 2 upgrades the verifier. Operators deploying Phase 1 should run behind a trusted network.

**In-process job queue has no durability**
→ If the process crashes mid-ingestion, in-flight jobs are lost. Acceptable for Phase 1 (restart reruns the upload). Phase 3 Redis queue adds durability.

**NVD API rate limits may disrupt CVE watch**
→ Exponential backoff + OSV as fallback feed. CVE watch failures are non-blocking; system continues with cached CVE data.

**risk_score is intentionally simplified in Phase 1**
→ No EPSS, KEV, or AI confidence. Score is raw severity + VEX status. This is documented and expected; Phase 2 enriches it. Do not treat Phase 1 scores as production risk assessments without context.

**No row-level security in Phase 1**
→ Product isolation is enforced at query level via API key scope. Database-level RLS is Phase 3. Operators must ensure the API is not exposed without the API key layer.

**SBOM component count limits**
→ Large SBOMs (10K+ components) are parsed with a configurable timeout (default 5 min) and component count limit (default 50K). Exceeding limits results in REJECTED status with a descriptive error.

---

## Open Questions

| Question | Owner | Target |
| -------- | ----- | ------ |
| Which LLM/provider for Phase 2 AI enrichment? (Claude API assumed) | Architecture | Phase 2 OpenSpec |
| Commit signing (GPG on git commits) — verify in Phase 2 git ingestion? | Security | Phase 2 OpenSpec |
| SBOM component count limit — what is the right default cap? | Engineering | Phase 1 implementation |
| Should `cve_watch` poll NVD only, or OSV first with NVD fallback? | Engineering | Phase 1 implementation |
