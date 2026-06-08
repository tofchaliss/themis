# Themis — Project Context

Themis is an open-source Go backend security intelligence platform. It ingests SBOM and VEX
documents, correlates vulnerabilities, applies VEX overlay semantics, watches for newly
disclosed CVEs, and delivers notifications. Built as a standalone binary backed by PostgreSQL.

---

## Core Concepts

| Term | Meaning |
| ---- | ------- |
| SBOM | Software Bill of Materials — CycloneDX or SPDX format document listing all components in an artifact |
| VEX | Vulnerability Exploitability eXchange — overlay document that contextualises raw findings without deleting them |
| PURL | Package URL — canonical component identity used for CVE matching and deduplication |
| risk_context | The convergence table — computed effective state combining all three data layers |
| effective_state | The live status of a finding: DETECTED, SUPPRESSED, CONFIRMED, IN_TRIAGE, ACCEPTED_RISK, FALSE_POSITIVE, RESOLVED |
| VEX overlay | VEX assertions change only effective_state in risk_context; raw findings in component_vulnerabilities are never deleted or modified |
| L1 / L2 / L3 | The three data layers (see below) |
| InProcessQueue | Phase 1 goroutine-pool implementation of the JobQueue domain interface |

---

## Three-Layer Data Model (permanent, all phases)

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
          Phase 1: populated by VEX overlay computation only.
          Phase 2: EPSS/KEV sync adds scored signals.
          Phase 3: AI signals.

  CONVERGENCE
  ───────────
  Table:  risk_context — single source of truth for current vulnerability status
  Score:  Phase 1 = f(raw_severity, vex_effective_state)
          Phase 2 = f(raw_severity, vex_effective_state, EPSS, KEV)
          Phase 3 = f(all signals + AI scoring)
```

---

## Clean Architecture (mandatory, all phases)

All code follows Robert C. Martin's Clean Architecture. The Dependency Rule is absolute:
**source code dependencies can only point inward**.

```text
  cmd/themis/main.go          ← DI root only; wires everything together
  internal/infrastructure/    ← Layer 4: pgx, chi, config, queue, metrics
  internal/adapter/           ← Layer 3: parsers, store, API handlers, notify, trust
  internal/usecase/           ← Layer 2: ingestion, enrichment, triage, watch
  internal/domain/            ← Layer 1: pure types + port interfaces (stdlib only)

  IMPORT RULE
  domain/      → stdlib only
  usecase/     → domain/ only
  adapter/     → domain/, usecase/
  infrastructure/ → all inner layers
  cmd/         → infrastructure/ only
```

Enforced by `go-cleanarch` and `depguard` in `.golangci.yml`. CI fails on any violation.

---

## Technology Stack

| Concern | Choice | Notes |
| ------- | ------ | ----- |
| Language | Go 1.22+ | Single binary distribution |
| Database | PostgreSQL only | No SQLite, no Redis in Phase 1 |
| Router | chi | HTTP routing and middleware |
| DB driver | pgx/v5 | PostgreSQL driver |
| Migrations | golang-migrate | SQL files versioned in repo |
| OpenAPI | oapi-codegen | Generates Go stubs from openapi.yaml |
| Logging | zap | Structured JSON logs |
| Metrics | prometheus/client_golang | /metrics endpoint |
| Tracing | OpenTelemetry | Spans across ingestion pipeline |
| Lint | golangci-lint + depguard + go-cleanarch | Import direction enforcement |
| Coverage | go test -coverprofile + scripts/check-coverage.sh | 100% domain, ≥90% infra |
| Dead code | golang.org/x/tools/cmd/deadcode | Zero tolerance |
| Job queue | InProcessQueue (goroutine pool) | Phase 1; swappable to Redis in Phase 3 |
| Sig verify | StubVerifier | Phase 1 stub; real cosign/sigstore in Phase 2 |

---

## Code Quality Gates (every task group)

Every task group must pass its gates before moving forward. **Coverage is task-wise; the clean rebuild is codebase-wide** — they are separate checks, run in this order:

### 1. Task-wise gates (packages touched by the group)

Run only what the group's section in `tasks.md` requires, scoped to that group's package(s):

1. **Unit tests** — `go test ./internal/<package>/...`
2. **Coverage** — `make coverage-pkg PKG=<path>` (e.g. `PKG=usecase/enrichment`; register new packages in `scripts/check-coverage.sh` first). Threshold: 100% for domain/usecase/parser/trust/notify; ≥90% for store/api/infrastructure.
3. **Dead code** — `make deadcode` when the group lists it
4. **Integration tests** — `go test -tags=integration ./internal/<package>/...` for the group's integration gate
5. **Clean Architecture** — `make clean-arch` when the group lists it

Full-repo coverage (`make coverage`) is reserved for final acceptance (Group 15) and CI-style sweeps.

### 2. Full codebase build (always, after task-wise gates pass)

6. **Clean rebuild** — `make verify-build` (`make clean` then `make all`) on the **entire repo**; confirms the binary still builds from scratch after the group's changes.

---

## Phase Roadmap

### Phase 1 — Standalone Go Backend (current)

**Goal:** Working REST API with no external AI, CI/CD, or UI dependencies.

**Capabilities:**

| Capability | Description |
| ---------- | ----------- |
| artifact-trust | Schema validation, hash verification, deduplication, provenance check, StubVerifier |
| sbom-parser | CycloneDX 1.4/1.5/1.6, SPDX 2.3/3.0, Trivy JSON → CanonicalSBOM |
| sbom-ingestion | POST /api/v1/sbom/upload (202), POST /api/v1/webhooks/scan (HMAC-SHA256), async pipeline, idempotency |
| sbom-store | Three-layer PostgreSQL schema via golang-migrate, PURL-indexed component catalog |
| intelligence-enrichment | VEX overlay only; effective state machine; Phase 1 risk score = severity + VEX state |
| cve-triage | L4 human triage API; themis-generated VEX from decisions; immutable triage history |
| cve-watch | NVD/OSV scheduled polling (default 6h); PURL+version-range matching; ecosystem-batched queries |
| notification-service | SMTP + Teams Adaptive Card; configurable routing rules; digest aggregation |

**Key constraints:**

- No AI enrichment — Phase 2
- No EPSS / KEV signals — Phase 2
- No real cosign verification — StubVerifier only; real sigstore in Phase 2
- No CI/CD git integration — Phase 2
- No web UI — Phase 3
- No Docker production stack — Phase 3
- No Redis queue — Phase 3
- No full RBAC/OIDC — Phase 3
- API key auth only (`X-API-Key`, bcrypt-hashed, product-scoped)

**Ingestion pipeline lifecycle:**

```text
RECEIVED → VALIDATING → CORRELATING → ENRICHING → COMPLETED → NOTIFIED
                │               │
                ▼               ▼
            REJECTED          FAILED (retryable)
```

**OpenSpec artifacts:** `openspec/changes/themis-phase-1/`

---

### Phase 2 — AI Intelligence + CI/CD Integration

**Goal:** Add AI-driven enrichment, real cosign verification, EPSS/KEV signals, and automated
git-triggered ingestion from GitHub and GitLab.

**Planned capabilities:**

| Capability | Description |
| ---------- | ----------- |
| ai-enrichment | LLM-based vulnerability analysis (Claude API assumed); AI signals populate L3 |
| epss-kev-sync | EPSS scores + CISA KEV feed populate intelligence_signals in L3 |
| cosign-verifier | Real sigstore/cosign cryptographic signature verification (replaces StubVerifier via interface swap) |
| github-integration | GitHub webhook + repo polling; auto-ingest SBOM/VEX pushed to a repo |
| gitlab-integration | GitLab webhook + repo polling; same pipeline as GitHub |
| upstream-vex-feeds | Pull VEX from Red Hat, Alpine, Ubuntu, SUSE, Wolfi, Rocky Linux |
| vex-export | Export Themis risk_context as a VEX document |
| rate-limiting | Per-product API rate limiting |

**Key decisions already made:**

- GitHub + GitLab only in Phase 2; Bitbucket moves to Phase 3
- Phase 2 is "predominantly AI interfacing" — git integration supports AI by providing the artifact source
- CI/CD integration means: if a repo has SBOM/VEX committed, Themis auto-downloads and ingests on push
- Risk score formula gains EPSS and KEV multipliers
- The `IngestionService` interface (defined in Phase 1) is called by git handlers — no pipeline duplication

**OpenSpec artifacts:** to be created as `openspec/changes/themis-phase-2/`

---

### Phase 3 — Enterprise Production Stack

**Goal:** Production-ready deployment, UI, horizontal scaling, and enterprise auth.

**Planned capabilities:**

| Capability | Description |
| ---------- | ----------- |
| docker-compose | Full production Docker Compose stack for self-hosted deployment |
| redis-queue | Swap InProcessQueue for RedisQueue via the JobQueue interface — zero business logic change |
| web-ui | React SPA dashboard for vulnerability management, triage, and reporting |
| bitbucket-integration | Bitbucket webhook + repo polling (delayed from Phase 2) |
| rbac-oidc | Full role-based access control with OIDC/OAuth2; replaces Phase 1 API key auth |
| ha-deployment | Multi-instance deployment with shared PostgreSQL and Redis |
| themis-cli | Standalone CLI tool for local SBOM analysis without a running server |

**Key decisions already made:**

- Docker everything moves to Phase 3 entirely
- Redis queue swap requires only changing `internal/infrastructure/queue/` — use cases unaffected
- UI requires more design discussion before OpenSpec

**OpenSpec artifacts:** to be created as `openspec/changes/themis-phase-3/`

---

## API Conventions (all phases)

- **Versioning:** `/api/v1/` prefix; breaking changes get `/api/v2/`
- **Pagination:** cursor-based on all list endpoints (`?cursor=...&limit=50`)
- **Errors:** RFC 7807 Problem Details `{type, title, status, detail, instance}`
- **Async:** upload and webhook endpoints return `202 Accepted`; processing is async via JobQueue
- **Idempotency:** `Idempotency-Key` header on all mutating endpoints
- **Auth (Phase 1):** `X-API-Key` header; keys are product-scoped; bcrypt-hashed in DB
- **Webhook auth:** HMAC-SHA256 `X-Themis-Signature` header

---

## VEX Overlay Semantics (permanent invariant)

Raw findings in `component_vulnerabilities` are **never deleted, modified, or suppressed**.
VEX assertions change only `risk_context.effective_state`. This means:

- A suppressed finding can always resurface if the VEX is revoked
- Triage history is append-only; the most recent decision wins
- L4 human triage decisions auto-generate a `vex_document` with `source=themis_generated`
- Generated VEX auto-applies to future ingestions of the same `(component_purl, cve_id)` pair

---

## Trust Policy Levels (per product)

```text
strict      Require signed SBOM, verified supplier, complete provenance.
            Reject unsigned or unverifiable artifacts.
standard    Accept unsigned (trust_status=unsigned). Require valid schema.
            Log missing provenance as warnings. (Default)
permissive  Accept all valid-schema artifacts. For testing/dev only.
```

Phase 1: signature fields recorded but not cryptographically verified (StubVerifier).
Phase 2: real cosign/sigstore verification replaces StubVerifier via interface swap.

---

## Detailed Specifications

| Document | Contents |
| -------- | -------- |
| `proposal-initial.md` | Original 9 ADRs, 15 acceptance criteria, 8 capabilities — source of truth for design decisions |
| `openspec/changes/themis-phase-1/proposal.md` | Phase 1 scope and capability list |
| `openspec/changes/themis-phase-1/design.md` | 17 design decisions including Clean Architecture and code quality gates |
| `openspec/changes/themis-phase-1/tasks.md` | ~100 implementation tasks across 15 groups with 6 mandatory gates each |
| `openspec/changes/themis-phase-1/specs/*/spec.md` | Per-capability requirements and acceptance scenarios |
