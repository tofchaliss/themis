# Themis — Installation & Configuration

How to build, configure, and run Themis. There are two deployables:

- **Phase-3 greenfield services** (the go-forward) — independent bounded-context binaries under `cmd/`.
- **v0.3.x single binary** (`cmd/themis`) — the frozen monolith, kept as reference.

For exercising a running system (SBOM upload, the Intelligence Gateway, verification) see
[TESTING.md](TESTING.md); for the HTTP surface see [API.md](API.md).

---

## Prerequisites

| Requirement | Version | Notes |
| ----------- | ------- | ----- |
| Go | 1.25+ | Must match `go` in `go.mod` |
| PostgreSQL | 14+ (16 recommended) | Running and reachable before you start Themis |
| golangci-lint | v2.x | Only for `make check` / contributing |

The binaries need no runtime dependency beyond PostgreSQL. The Intelligence Gateway additionally needs a
model runtime **only when AI is enabled** (Ollama — see [below](#intelligence-gateway-optional-ai)).

---

## Part A — Phase-3 greenfield services

The pipeline is **Evidence → Knowledge → Governance → Communication**, over a **Registry/Kernel**
foundation, with a supporting **Intelligence Gateway** beside it. Each is its own binary + Postgres schema
and collaborates only via events + read APIs (no shared tables).

| Service | Command | Port | Migrations env |
| ------- | ------- | ---- | -------------- |
| Registry | `cmd/registry` | `:8082` | `THEMIS_REGISTRY_MIGRATE=1` |
| Evidence | `cmd/evidence` | `:8081` | `THEMIS_EVIDENCE_MIGRATE=1` |
| Governance | `cmd/governance` | `:8083` | `THEMIS_GOVERNANCE_MIGRATE=1` |
| Communication | `cmd/communication` | `:8084` | `THEMIS_COMMUNICATION_MIGRATE=1` |
| Intelligence | `cmd/intelligence` | `:8086` | — (stateless) |

> Knowledge/Faultline is implemented under `internal/knowledge`; its standalone service wiring lands with
> the **M5 event bus** (which also carries the cross-context events — today each context relays to a logging
> stand-in). See [`docs/engineering/PHASE3-STATUS.md`](docs/engineering/PHASE3-STATUS.md).

### Build & gate

```sh
go build ./...     # builds every service
make check         # build · lint · clean-arch · arch-test · coverage (+ integration) · deadcode
```

### Configure

Every option for every service is documented inline in [`deploy/node.env.example`](deploy/node.env.example)
— copy it, fill in the values for the service you're running, and export them. Shared essentials:

```sh
export THEMIS_DATABASE_DSN="postgres://themis:CHANGEME@localhost:5432/themis?sslmode=disable"  # required by persisting services
export THEMIS_LOG_LEVEL=info          # debug | info | warn | error
export THEMIS_LOG_FORMAT=json         # json (prod) | console (dev)
# OpenTelemetry log export is OFF unless an endpoint is set:
export THEMIS_OTLP_LOGS_ENDPOINT=     # e.g. otel-collector:4318
```

### Run a service

Each service applies its own migrations on request and serves under `/api/v1`:

```sh
THEMIS_REGISTRY_MIGRATE=1     go run ./cmd/registry       # :8082
THEMIS_EVIDENCE_MIGRATE=1     go run ./cmd/evidence       # :8081
THEMIS_GOVERNANCE_MIGRATE=1   go run ./cmd/governance     # :8083
THEMIS_COMMUNICATION_MIGRATE=1 go run ./cmd/communication # :8084
```

(Use one database; each service owns its own tables/migrations within it.)

### Intelligence Gateway (optional AI)

`cmd/intelligence` is **stateless** (no database) and part of the **optional AI plane** — the pipeline is
fully correct with it off (disabled ≡ unavailable). It turns a Governance Finding into an **advisory**
position recommendation that a human still decides.

**Provider** (config-selected):

- **Fake (no model):** `THEMIS_INTELLIGENCE_PROVIDER=fake` — for wiring/smoke tests without Ollama.
- **Ollama (real, local-first):** `THEMIS_OLLAMA_URL` (default `http://localhost:11434`) +
  `THEMIS_INTELLIGENCE_MODEL` (default `llama3.1:8b`). On **macOS run Ollama natively** for Metal GPU
  acceleration — a container on a Mac is CPU-only. In a cluster, run the Ollama container as its own Service.

```sh
# real:
ollama serve &            # native on macOS (Metal GPU)
ollama pull llama3.1:8b
go run ./cmd/intelligence # :8086, grounds via THEMIS_GOVERNANCE_URL + THEMIS_KNOWLEDGE_URL
```

**The disable gate (D13)** is one wiring choice on the *Governance* service — no call-site flags:

```sh
# AI OFF (default): don't run cmd/intelligence; leave the flag unset → Governance wires a no-op advisor.
# AI ON:
export THEMIS_GOVERNANCE_AI_ENABLED=1
export THEMIS_INTELLIGENCE_URL=http://localhost:8086
```

Design: [`docs/engineering/decisions/EDR-INTELLIGENCE-01.md`](docs/engineering/decisions/EDR-INTELLIGENCE-01.md)
(Revision 2) + [`docs/engineering/THEMIS-AI-HARNESS.md`](docs/engineering/THEMIS-AI-HARNESS.md).

---

## Part B — v0.3.x single binary (`cmd/themis`)

The frozen monolith: one binary, one API (`/api/v1`), one Postgres schema.

> **No in-place upgrade** from a pre-`v0.3.0` database — drop and recreate (see
> [TESTING.md § Resetting data](TESTING.md#resetting-ingested-data-local-dev-only)).

### 1. PostgreSQL, database & role

```sh
brew services start postgresql@16          # macOS/Homebrew; or your platform's start
psql -U postgres -c "CREATE USER themis WITH PASSWORD 'themis-dev-password';"
psql -U postgres -c "CREATE DATABASE themis OWNER themis;"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE themis TO themis;"

export THEMIS_DATABASE_DSN="postgres://themis:themis-dev-password@localhost:5432/themis?sslmode=disable"
psql "$THEMIS_DATABASE_DSN" -c 'SELECT 1;'  # verify it connects
```

### 2. Build, configure, migrate, run

```sh
make build                       # → ./bin/themis
cp themis.yaml.example themis.yaml   # optional non-secret defaults; secrets go in env vars only
make migrate-up                  # THEMIS_DATABASE_DSN must be exported (startup also auto-migrates)
./bin/themis                     # serves on :8080
```

### 3. Health & an API key

```sh
curl -s localhost:8080/healthz            # {"status":"ok"}
curl -s localhost:8080/readyz | jq .      # checks.database = "ok"
./bin/themis admin create-key --admin --expires 90d   # --product-id <uuid> in production
```

API calls then require `X-API-Key`; webhooks use HMAC-SHA256 (`X-Themis-Signature`). Revoke with
`./bin/themis admin revoke-key --key-id <id>`.

---

## Configuration reference (v0.3.x)

Themis reads `themis.yaml` (optional) and environment variables; **env vars override YAML**. **Secrets**
(DSN, SMTP password, API keys) must be set via environment variables — never committed in `themis.yaml`.

### Core

| Variable | Required | Purpose |
| -------- | -------- | ------- |
| `THEMIS_DATABASE_DSN` | **Yes** | PostgreSQL connection URL |
| `THEMIS_CONFIG_PATH` | No | Path to YAML config (default `./themis.yaml`) |
| `THEMIS_NVD_API_KEY` | No | NVD API key (higher CVE-watch rate limits) |
| `THEMIS_SMTP_*` | No | Outbound email (`HOST`, `PORT`, `USERNAME`, `PASSWORD`, `FROM`, `USE_TLS`) |
| `THEMIS_TEAMS_WEBHOOK_URL` | No | Microsoft Teams webhook |
| `THEMIS_WEBHOOK_SECRET` | No | HMAC secret for CI webhook ingestion |
| `THEMIS_TRUST_DEFAULT_POLICY` | No | `strict` \| `standard` \| `permissive` |
| `THEMIS_LOG_LEVEL` | No | `debug` \| `info` \| `warn` \| `error` |

### Signal feeds & intelligence (background schedulers, default 24h)

These fetch external data and **retroactively re-enrich** open findings (no re-upload needed).

- **EPSS + KEV** (`epsskev` / `THEMIS_EPSSKEV_*`) — FIRST.org EPSS scores + CISA KEV; feed `epss_score`
  and `kev_listed`.
- **ExploitDB** (`exploitdb` / `THEMIS_EXPLOITDB_*`) — public-exploit records → `exploit_public`.
- **Upstream vendor feeds** (`vexfeed` / `THEMIS_VEXFEED_*`) — Red Hat CSAF **VEX** (overlay) vs Red Hat
  CSAF advisories + Alpine/Rocky/Wolfi **OSV** (correlation, apk/rpm). A `vexfeed.feeds:` delta list can
  add/override/disable feeds by name. See [`themis.yaml.example`](themis.yaml.example).
- **Other:** `intelligence.blast_radius_cap` (unique-customer count where the multiplier caps, default 10 →
  max 2.0×); `THEMIS_GITHUB_TOKEN` (GHSA — wired, adapter not yet used).

**Risk score** is composite: severity baseline + EPSS (+30% max) + KEV (+15) + blast-radius multiplier
(1.0–2.0×) + a Layer-1 Critical override (`score = 100`).

### Database migrations

```sh
make migrate-up      # apply all pending (THEMIS_DATABASE_DSN must be exported)
make migrate-down    # roll back one
```

Migration SQL is a single squashed `v0.3.0` baseline under `migrations/`. A startup **schema-skew guard**
refuses to start against a pre-`v0.3.0` database — there is no in-place upgrade.

---

## Project layout (reference)

```text
themis/
├── cmd/
│   ├── themis/            v0.3.x monolith (DI root)
│   ├── registry/ evidence/ governance/ communication/ intelligence/   Phase-3 services
├── internal/
│   ├── kernel/ registry/                        Phase-3 shared foundation
│   ├── evidence/ knowledge/ governance/ communication/ intelligence/   Phase-3 contexts ({domain,app,adapters})
│   ├── platform/observability/                  shared zap + OpenTelemetry logging
│   ├── domain/ usecase/ adapter/ infrastructure/  v0.3.x Clean-Architecture layers (frozen)
│   └── testutil/gen/                            shared rapid generators
├── api/                  OpenAPI specs (monolith + one per Phase-3 context)  → API.md
├── deploy/node.env.example   fully-commented per-service config
├── migrations/           v0.3.x squashed baseline (Phase-3 migrations live per-context)
└── docs/                 architecture book, ADRs, engineering notes, release notes
```
