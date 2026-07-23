# Phase-3 Greenfield — Technology Stack & Rationale

**Updated:** 2026-07-15 · **Read before any `/opsx:apply`.** This is the canonical, justified technology
stack for the Phase-3 greenfield rebuild. Every OpenSpec change (`phase3-*`) grounds its implementation on
this document so choices are consistent and defensible — not decided ad-hoc per task.

## Ground rules

- **Carry the proven PoC stack forward.** The `internal/` PoC already runs a deliberate, working stack; the
  greenfield reuses it rather than re-litigating settled infrastructure. New dependencies require a stated
  reason here first.
- **ADR wins.** Where the ADRs constrain a choice (provider independence, transactional outbox, structured
  telemetry, standards-only formats), the ADR is the reason of record.
- **Standards-first, provider-independent.** Prefer open standards (OpenAPI, CycloneDX/OpenVEX/CSAF, JSON
  Schema, OpenTelemetry). All AI/provider-specific code stays confined to the Intelligence Gateway
  (INT-0070).
- **Cross-cutting build rules** live in **`docs/engineering/CONVENTIONS.md`** — read alongside this doc:
  R1 every node logs to **console + OpenTelemetry**; R2 configuration is **self-documented in the config
  file with comments**.

## Core stack (in use today; carried forward)

| Concern | Choice | Why | Ref |
| --- | --- | --- | --- |
| Language / runtime | **Go 1.25** | Single static binary, first-class concurrency for background workers + outbox relays, the PoC's language | PoC |
| Datastore | **PostgreSQL** via **`jackc/pgx/v5`** | ACID single-DB transactions are required by the **transactional outbox** (record + event in one commit); pgx is the performant native driver | BCK-0040/0041 |
| Migrations | **`golang-migrate/migrate/v4`** (postgres tag) | Versioned, **reversible** up/down migrations — each context owns its own tables; up/down reversibility is a task gate | Book III §3.5 |
| HTTP router | **`go-chi/chi/v5`** | Lightweight, idiomatic, no framework lock-in; std-lib `net/http` compatible | PoC |
| API contract | **`oapi-codegen/v2`** + **`getkin/kin-openapi`** | **Spec-first REST** — OpenAPI is the source of truth, handlers generated (`make generate-api`); consistent error-UX envelope | BCK-0048 |
| Schema validation | **`santhosh-tekuri/jsonschema/v6`** | Validates inbound SBOM/VEX (Evidence trust-gate) **and** the schema stage of Intelligence's 3-stage response validation | EVID D4 · INT-0057/0063 |
| Identity | **`google/uuid`** | Opaque, stable internal aggregate IDs (Faultline / Finding / Publication / Evidence own-identity) | DOM-0027 |
| Observability | **OpenTelemetry** (`go.opentelemetry.io/otel` traces/metrics/logs) | The architectural telemetry standard — correlation-id-driven, vendor-neutral; the Intelligence Gateway standardizes on it (+ console log for local debug) | BCK-0051 · INT-0064 |
| Metrics | **`prometheus/client_golang`** | Existing operational metrics; complements OTel | BCK-0051 |
| Structured logging | **`go.uber.org/zap`** | Structured logs correlated by business identifier (not debug print) | BCK-0051 |
| Config | **`gopkg.in/yaml.v3`** | Existing config format | PoC |

## Testing & quality

| Concern | Choice | Why | Ref |
| --- | --- | --- | --- |
| Unit / table tests | std-lib `testing` | Default; fast, no framework | PoC |
| Property tests | **`pgregory.net/rapid`** | Reconciliation/precedence rules, version-matching, and materialization invariants benefit from property-based coverage | KNOW D2 · COMM D3 |
| Integration DB | **`fergusstrange/embedded-postgres`** | Real Postgres in-process — genuine outbox/concurrency/migration tests without external infra | BCK-0041/0043 |
| Clean-arch enforcement | **`roblaszczak/go-cleanarch`** + **depguard** | Enforces inward-only ring rules + **no cross-context imports** — every context ships an architecture test | BCK-0037/0038/0039 |
| Lint | **`golangci-lint`** | Aggregate linters incl. depguard | PoC |
| Docs lint | **`markdownlint-cli2`** (MD013 = 120) | All repo docs lint clean | repo convention |

**Quality gate (`make check`):** build · lint (golangci-lint) · clean-arch (go-cleanarch) · coverage
(`scripts/check-coverage.sh`) · deadcode (`x/tools`) · integration tests. Each `tasks.md` group ends here.

## Greenfield additions (add during implementation, with reason)

| Concern | Choice | Why | Ref |
| --- | --- | --- | --- |
| Event infrastructure (M5) | **Postgres-outbox + relay** (no external broker to start) | BCK-0041 needs exactly-once-eventually; a DB-backed outbox meets it without operating Kafka/NATS. A broker can slot behind the same envelope later | KERN D4 · BCK-0041 |
| SBOM/VEX formats | **CycloneDX / SPDX** (in), **CycloneDX VEX / OpenVEX / CSAF** (out) | Standards-only, extensible ACL/serializer registries — no tool-specific dialects leak into the domain | EVID D4 · COMM D7 · BCK-0052 |
| AI providers (Intelligence only) | **local-first (Ollama HTTP)** + optional cloud, behind a uniform **provider port** | Provider-independent; sensitive data stays local; provider code confined to the Gateway `adapters/` | INT-0069/0070 · D4/D10 |
| Vector store / RAG (Intelligence, autonomous) | **pgvector** (deferred) | Only if the autonomous engine needs embeddings retrieval; reactive-first ships without it | INT-0068 · INTEL D3 |

## Per-context notes

- **Shared Kernel** — pure Go value objects (no deps beyond `uuid`); registry uses pgx + migrate.
- **Evidence / Knowledge / Governance / Communication** — identical three-ring stack: pgx + migrate (own
  tables), chi + oapi-codegen (read/write API), Postgres-outbox relay, OTel + zap. Communication adds the
  format serializers; Knowledge adds the feed ACLs.
- **Intelligence** — the Gateway is an independently-deployable Go service; all provider SDKs live behind
  the provider port in `adapters/`; jsonschema for response validation; OTel for the mandatory execution
  telemetry; **no truth-store driver** (it reads via read APIs, writes via proposal-intake).

## Not chosen (and why)

- **ORM (GORM/ent)** — rejected; hand-written SQL via pgx keeps aggregate-root persistence explicit and the
  outbox transaction precise.
- **Heavy web framework (Gin/Echo/Fiber)** — rejected; chi + std-lib is sufficient and lock-in-free.
- **External message broker (Kafka/NATS) up front** — deferred; the Postgres outbox satisfies the ADR
  guarantee with far less operational surface.
