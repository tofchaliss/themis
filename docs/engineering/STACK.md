# Phase-3 Greenfield — Technology Stack & Rationale

**Updated:** 2026-08-03 · **Read before any `/opsx:apply`.** This is the canonical, justified technology
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
| Schema validation | **`santhosh-tekuri/jsonschema/v6`** | Validates the schema stage of Intelligence's 3-stage response validation, and guards the event integration-contract v1 in each context's store contract test. **Not** the Evidence trust-gate: that checks well-formedness only (`json.Valid`) — schema validation of inbound SBOM/VEX is open as parity gap **E1** | INT-0057/0063 · EDR-EVENTBUS-01 D3 · (EVID D4 = E1, open) |
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
| Docs lint | **`markdownlint-cli2`** (MD013 = 120; tables + headings exempt) | Clean and kept clean: `CLAUDE.md`, `README.md`, `API.md`, this file, `CONVENTIONS.md`, `PARITY-GAP.md`, and **all 12 decision records**. **Known residue (measured 2026-08-10, not a gate):** `docs/BACKLOG.md` 266 · `PHASE3-STATUS.md` 13 · `INSTALLATION.md` 3 · `TESTING.md` 1 — long-lived append-mostly logs where reflowing old entries would churn history for no reader benefit. It is **not** in `make check`, so treat it as a pre-commit habit on the docs you touched | repo convention |

**Quality gate (`make check`):** build · lint (golangci-lint) · clean-arch (go-cleanarch) · coverage
(`scripts/check-coverage.sh`) · deadcode (`x/tools`) · integration tests. Each `tasks.md` group ends here.

## Greenfield additions (add during implementation, with reason)

| Concern | Choice | Why | Ref |
| --- | --- | --- | --- |
| Event infrastructure (M5) | **Postgres-outbox + relay + `bus` event_log + stream Reader** (no external broker) — **realized 2026-07-29** | BCK-0041 needs exactly-once-eventually; a DB-backed outbox → `bus.event_log` → per-consumer inbox meets it without operating Kafka/NATS. Publisher/Reader ride the kernel `Envelope`, so a broker can slot behind the same ports later (D1/D2) | KERN D4 · BCK-0041 · EDR-EVENTBUS-01 |
| SBOM/VEX formats | **CycloneDX / SPDX** (in), **CycloneDX VEX / OpenVEX / CSAF** (out) | Standards-only, extensible ACL/serializer registries — no tool-specific dialects leak into the domain | EVID D4 · COMM D7 · BCK-0052 |
| AI providers (Intelligence only) | **local-first (Ollama HTTP)** + optional cloud, behind a uniform **provider port** | Provider-independent; sensitive data stays local; provider code confined to the Gateway `adapters/` | INT-0069/0070 · D4/D10 |
| Vector store / RAG (Intelligence, **Δ3 reactive**) | **In-memory Go cosine over embeddings persisted in a plain Postgres table** (`float4[]`/`bytea`, **no pgvector**), behind an `app.VectorIndex` port; **pgvector**/Qdrant = upgrade paths | Corpus = the enterprise's own Positions/Findings (≤~50k, low QPS): brute-force search ~47 ms/query (measured), no extension, no `embedded-postgres` test gap, persists (no re-embed on boot). Grounds the reactive `recommend_position` (G-AI-3) — **not autonomous-only**. Scales via the port past ~10⁶ | INT-0068 · EDR-INTELLIGENCE-01 Rev 4 · `RAG-*.md` |
| Embedding model (Intelligence, Δ3) | **`nomic-embed-text`** (768) via the local Ollama runtime — **confirmed by the R5 eval, 2026-08-05** | Local/private (D10), reuses the deployed runtime, PoC precedent. `make e2e-embed` on the VM Ollama measured recall@1 = 1.00 / MRR = 1.00 / ~46 ms with the `components+severity` composition (`+cve` neutral, `+description` **hurts** at 0.83); bge/e5 (384) only if memory/latency demand | D10 · EDR-INTELLIGENCE-01 Rev 4 (R5) · `RAG-SESSION-2-SPIKE.md` §4 |
| Inbound-edge auth (F1) | **`golang.org/x/crypto/bcrypt`** for the API-key hash | The `auth` store keeps only a bcrypt hash of each token, never the token (EDR-SECURITY-01 D1). bcrypt over SHA-2 because an API key is a credential, not a content digest: the deliberate work factor is the point. Carried forward, not new: `go.mod` has held it since Phase 1 for the PoC's own key store — `internal/platform/auth` is the greenfield consumer | EDR-SECURITY-01 D1 |

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
- **Dedicated vector DB (Qdrant/Milvus/Weaviate) for RAG** — deferred; the Δ3 index is the enterprise's
  own ≤~50k Positions/Findings at low QPS, far below the 10⁷–10⁹/high-QPS regime these are built for. A
  plain-Postgres vector table + in-memory Go search meets it with no new service; a dedicated store slots
  behind the `app.VectorIndex` port if the corpus ever outgrows memory (~10⁶). See EDR-INTELLIGENCE-01 Rev 4.
- **Python RAG framework (LlamaIndex/LangChain) for retrieval** — rejected for Δ3; Themis's corpus is
  **structured records** (one embedding each), not documents, so their ingestion/chunking value does not
  apply, and they would duplicate the Gateway's Go-owned context/prompt/validation (D5/D6/D7). Python
  (DSPy) is reserved for a Δ3b *reasoning* engine behind the provider port, only if needed.
