# Themis

Themis is an open-source Go backend security intelligence platform. It ingests SBOM and VEX
documents, correlates vulnerabilities against live CVE feeds, applies VEX overlay semantics,
and delivers actionable notifications — all without touching your build system.

A single binary backed by PostgreSQL. No agents. No daemons. No lock-in.

---

## What Themis Does

| Capability | Description |
| ---------- | ----------- |
| **Artifact trust** | Schema validation, SHA-256 integrity, deduplication, provenance checks on every SBOM and VEX document ingested |
| **SBOM parsing** | CycloneDX 1.4/1.5/1.6, SPDX 2.3/3.0, and Trivy JSON — all normalised to one internal canonical model |
| **SBOM ingestion** | REST upload endpoint and HMAC-verified webhook; async pipeline with idempotency and lifecycle tracking |
| **Vulnerability correlation** | Component catalog matched against NVD and OSV by PURL and version range |
| **VEX overlay** | VEX assertions applied as a contextual layer; raw findings are never deleted — safe to revoke at any time |
| **CVE watch** | Background scheduler polls NVD/OSV every 6 hours; new findings auto-created for matching catalog components |
| **Human triage** | L4 triage API records decisions; each decision auto-generates a VEX assertion that applies to future ingestions |
| **Notifications** | SMTP and Microsoft Teams delivery with configurable routing rules and digest aggregation |

---

## Design Principles

### Clean Architecture

All code follows Robert C. Martin's Clean Architecture. The single most important rule:
**source code dependencies can only point inward**. Business logic never imports infrastructure.

```text
  cmd/themis/                  DI root — wires everything, imported by nothing
  internal/infrastructure/     Layer 4: pgx, chi, config, queue, metrics
  internal/adapter/            Layer 3: parsers, store, API handlers, notify, trust
  internal/usecase/            Layer 2: ingestion, enrichment, triage, CVE watch
  internal/domain/             Layer 1: pure types + port interfaces (stdlib only)
```

This means:

- Use cases are tested without a database, HTTP server, or any framework
- A new adapter (AI client, cosign verifier, Git provider) never touches business logic
- The job queue can be swapped from goroutines to Redis by changing one file

Enforced at compile time by `go-cleanarch` and `depguard`. CI fails on any import violation.

### Three-Layer Data Model

Vulnerability data is partitioned into three layers with different mutation rules:

```text
  L1 — IMMUTABLE INVENTORY
       products, images, sbom_documents, components, vulnerabilities
       Append-only. Never mutated. Never deleted. Content-addressed by SHA-256.

  L2 — MUTABLE INTELLIGENCE
       vex_documents, vex_assertions
       Each document is immutable. The collection evolves as new VEX arrives.

  L3 — TEMPORAL SIGNALS
       intelligence_signals, runtime_exposures
       Phase 1: VEX-derived only.  Phase 2: EPSS + KEV.  Phase 3: AI signals.

  CONVERGENCE → risk_context
       Single source of truth for the current state of every (component, CVE) pair.
```

### VEX Overlay — Raw Findings Are Never Deleted

VEX assertions change only `risk_context.effective_state`. The underlying
`component_vulnerabilities` record is always preserved. This means:

- A suppressed finding resurfaces immediately if the VEX is revoked
- Every state transition is auditable and reversible
- Human triage decisions auto-generate a `vex_document` that applies to future ingestions

---

## Phase Roadmap

### Phase 1 — Standalone Go Backend *(current)*

A complete, self-contained REST API. No external AI, CI/CD, or UI dependencies.

- All 8 capabilities listed above
- API key authentication (product-scoped, bcrypt-hashed)
- In-process goroutine job queue behind a swappable interface
- Cosign signature verification stubbed — records trust status without network calls
- PostgreSQL only, single binary deployment

### Phase 2 — AI Intelligence + CI/CD Integration

- **AI enrichment** — LLM-based vulnerability analysis (Claude API); AI signals in L3
- **EPSS + KEV** — CISA KEV feed and EPSS scores populate `intelligence_signals`
- **Real cosign** — sigstore/cosign cryptographic verification replaces the Phase 1 stub
- **GitHub + GitLab** — auto-ingest SBOM/VEX committed to a repo on push
- **Upstream VEX feeds** — Red Hat, Alpine, Ubuntu, SUSE, Wolfi, Rocky Linux
- **Rate limiting** — per-product API rate limits

### Phase 3 — Enterprise Production Stack

- **Docker Compose** — full production stack for self-hosted deployment
- **Redis job queue** — horizontal scaling; zero business logic change (interface swap)
- **Web UI** — React SPA for vulnerability management, triage, and reporting
- **Bitbucket integration** — git ingestion alongside GitHub/GitLab
- **RBAC + OIDC** — full role-based access control; replaces Phase 1 API keys
- **themis-cli** — standalone CLI for local SBOM analysis without a running server

---

## Prerequisites

| Requirement | Version | Notes |
| ----------- | ------- | ----- |
| Go | 1.22+ | `go version` |
| PostgreSQL | 14+ | For integration tests and running the server |
| golangci-lint | latest | `go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest` |

---

## Building

```sh
# Build the binary to bin/themis
make build

# Build and run all quality gates (lint + clean-arch + coverage + deadcode)
make check
```

The binary requires no runtime dependencies beyond PostgreSQL.

---

## Configuration

Themis reads configuration from a `themis.yaml` file and environment variables.
Environment variables override file values. All sensitive values (passwords, keys, URLs)
must be set via environment variables — never in config files.

**Minimum required environment variables:**

```sh
THEMIS_DATABASE_DSN="postgres://user:password@localhost:5432/themis?sslmode=disable"
```

**Quick start:**

```sh
cp themis.yaml.example themis.yaml
export THEMIS_DATABASE_DSN="postgres://user:password@localhost:5432/themis?sslmode=disable"
```

`THEMIS_DATABASE_DSN` is **required** — with or without `themis.yaml`. The file may leave
`database.dsn` empty when the DSN is supplied via the environment (recommended for secrets).

Optional: set `THEMIS_CONFIG_PATH` to use a config file somewhere other than `./themis.yaml`.

**Full reference (`themis.yaml` format):** see [`themis.yaml.example`](themis.yaml.example).

---

## Database Migrations

```sh
# Apply all pending migrations
THEMIS_DATABASE_DSN="..." make migrate-up

# Roll back one migration
THEMIS_DATABASE_DSN="..." make migrate-down
```

Migration SQL files live in `migrations/`. Themis refuses to start if the database
schema version is ahead of the binary version.

---

## Running

```sh
# Start the server (requires THEMIS_DATABASE_DSN; optionally reads themis.yaml)
export THEMIS_DATABASE_DSN="postgres://user:password@localhost:5432/themis?sslmode=disable"
./bin/themis

# Health and readiness
curl http://localhost:8080/healthz   # liveness
curl http://localhost:8080/readyz    # readiness (checks DB + CVE feed freshness)

# Prometheus metrics
curl http://localhost:8080/metrics
```

---

## API Key Management

Admin commands use the same config as the server (`themis.yaml` and/or `THEMIS_DATABASE_DSN`).

```sh
# Create a product-scoped key
./bin/themis admin create-key --product-id <id> --expires 90d

# Revoke a key
./bin/themis admin revoke-key --key-id <id>
```

All API calls require `X-API-Key: <key>` in the request header. Webhook endpoints
use HMAC-SHA256 (`X-Themis-Signature`).

---

## Testing

```sh
# Unit tests
make test

# Integration tests (requires PostgreSQL)
THEMIS_DATABASE_DSN="..." make test-integration

# Unit + integration with coverage report
THEMIS_DATABASE_DSN="..." make coverage
```

Integration tests use the `//go:build integration` tag and run against a real PostgreSQL
instance. The coverage report is written to `coverage.txt`.

### Property-Based Testing

Critical invariants are verified with property-based tests built on
[`pgregory.net/rapid`](https://github.com/flyingmutant/rapid) (a test-only dependency
with automatic shrinking and deterministic seed replay). They run as ordinary unit tests —
so they count toward the coverage gates and execute as part of `make test` and `make check` —
and can also be driven with a high example count for deep/nightly runs:

```sh
# Deep run: drives rapid with a high example count across all property-test packages
make test-property                 # defaults to 1000 examples per property
make test-property RAPID_CHECKS=20000
```

What the properties cover:

| Area | Example invariants |
| ---- | ------------------ |
| **Pure logic** | Risk score bounds `[0,100]` and monotonicity; PURL build/parse round-trips; version comparator laws; backoff bounds; redaction never leaks secrets; HMAC sign/verify round-trip |
| **Parser & trust** | Parsers never panic on arbitrary input and stay self-consistent; parsing is idempotent; checksum compare is case-insensitive; dedup keys are stable |
| **Stateful flows** | Triage history is append-only and never mutates raw findings (VEX-overlay invariant); ingestion only follows legal lifecycle transitions and is idempotent; the in-process queue loses no jobs and bounds retries |

Shared rapid generators live in `internal/testutil/gen/`. Property tests are named
`*Property` and discovered automatically by `make test-property`. When a property fails,
rapid prints a seed for deterministic replay; capture the shrunk counterexample as a
table-driven regression test. A nightly GitHub Actions workflow
(`.github/workflows/property-tests.yml`) runs the deep suite.

**Coverage targets:**

| Packages | Target |
| -------- | ------ |
| `internal/domain/`, `internal/usecase/*/`, `internal/adapter/parser/`, `internal/adapter/trust/`, `internal/adapter/notify/` | 100% |
| `internal/adapter/store/`, `internal/adapter/api/`, `internal/infrastructure/*/` | ≥ 90% |
| `cmd/`, generated OpenAPI stubs | Excluded |

---

## Code Quality

```sh
# Lint (golangci-lint + depguard)
make lint

# Clean Architecture import direction check
make clean-arch

# Dead code detection (zero tolerance)
make deadcode

# All gates in sequence
make check
```

Every task group must pass all six gates before being considered complete:
build → unit tests → coverage → dead code → integration tests → clean architecture.

---

## Code Structure

```text
themis/
├── cmd/
│   └── themis/
│       └── main.go              DI root — wires all layers together
│
├── internal/
│   ├── domain/                  Layer 1: pure types + port interfaces
│   │   ├── sbom.go              CanonicalSBOM, CanonicalComponent
│   │   ├── vulnerability.go     Vulnerability, CVE types
│   │   ├── vex.go               VEXAssertion, EffectiveState
│   │   ├── product.go           Product, ProductVersion, Image
│   │   ├── risk.go              RiskContext, risk score types
│   │   └── ports.go             SBOMRepository, JobQueue, NotificationSender, etc.
│   │
│   ├── usecase/                 Layer 2: application business rules
│   │   ├── ingestion/           Orchestrate trust → parse → store → enrich → notify
│   │   ├── enrichment/          VEX overlay, state machine, risk score computation
│   │   ├── triage/              Human triage decisions, VEX generation, history
│   │   └── watch/               CVE feed polling, catalog matching, new findings
│   │
│   ├── adapter/                 Layer 3: interface adapters
│   │   ├── parser/              CycloneDX, SPDX, Trivy → CanonicalSBOM
│   │   ├── store/               PostgreSQL implementations of domain repositories
│   │   ├── notify/              SMTP + Teams delivery, routing rules, digest
│   │   ├── trust/               StubVerifier (Phase 1); CosignVerifier (Phase 2)
│   │   └── api/                 HTTP handlers, OpenAPI stubs, auth middleware
│   │
│   ├── infrastructure/          Layer 4: frameworks and drivers
│   │   ├── db/                  pgx connection pool, migration runner
│   │   ├── queue/               InProcessQueue (goroutine pool)
│   │   ├── http/                chi router setup, middleware registration
│   │   ├── config/              YAML + env var config loading
│   │   └── metrics/             Prometheus registration, OpenTelemetry setup
│   │
│   └── testutil/
│       └── gen/                 Shared rapid generators for property-based tests
│
├── migrations/                  SQL migration files (golang-migrate)
├── api/                         openapi.yaml — OpenAPI 3.1 specification
├── scripts/
│   └── check-coverage.sh        Enforces per-package coverage thresholds
├── Makefile
└── PROJECT_CONTEXT.md           Full multi-phase design reference
```

---

## Contributing

1. Run `make check` before every commit — all six gates must pass
2. No `TODO:` or `FIXME:` comments may be left at the end of a task group
3. Every new exported symbol needs a consumer (test or production caller) — `make deadcode` enforces this
4. Keep domain and use case packages free of framework imports — `make clean-arch` enforces this
5. Detailed design decisions, specs, and implementation tasks are in `openspec/changes/themis-phase-1/`

---

## License

[MIT](LICENSE)
