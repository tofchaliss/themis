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
foundation, with a supporting **Intelligence Gateway** beside it. Each is its own binary and **its own
database**, and since **M5** they collaborate over a real **event bus** (a dedicated `bus` PostgreSQL
database holding one `event_log`) plus read-only HTTP APIs — no shared business tables.

| Service | Command | Port | Own database | Reads over HTTP | Migrate on startup |
| ------- | ------- | ---- | ------------ | --------------- | ------------------ |
| Registry | `cmd/registry` | `:8082` | `evidence` (shared) | — | `THEMIS_REGISTRY_MIGRATE=1` |
| Evidence | `cmd/evidence` | `:8081` | `evidence` | Registry (in-proc) | `THEMIS_EVIDENCE_MIGRATE=1` |
| Knowledge | `cmd/knowledge` | `:8085` | `knowledge` | Evidence `:8081`, OSV | `THEMIS_KNOWLEDGE_MIGRATE=1` |
| Governance | `cmd/governance` | `:8083` | `governance` | Intelligence `:8086` (if AI on) | `THEMIS_GOVERNANCE_MIGRATE=1` |
| Communication | `cmd/communication` | `:8084` | `communication` | Governance `:8083` | `THEMIS_COMMUNICATION_MIGRATE=1` |
| Intelligence | `cmd/intelligence` | `:8086` | — (stateless) | Governance `:8083`, Knowledge `:8085` | — |
| **bus** | — | — | `bus` | — | `THEMIS_BUS_MIGRATE=1` (any pipeline svc) |

> **The event bus is the end-to-end switch.** Each of the four pipeline services relays its outbox to the
> bus and drains its upstream stream on a 2-second loop **only when `THEMIS_BUS_DATABASE_DSN` is set**. Leave
> it unset and the service falls back to a logging stand-in publisher with its reader disabled — a single
> context runs, but **an uploaded SBOM never crosses into Knowledge / Governance / Communication**. For an
> end-to-end SBOM→VEX flow, every pipeline service must point `THEMIS_BUS_DATABASE_DSN` at the same `bus`
> database.

> **Port gotcha (`cmd/knowledge`).** Its `THEMIS_KNOWLEDGE_ADDR` default is `:8082`, which **collides with
> Registry**. The rest of the system expects Knowledge on **:8085** (Intelligence's `THEMIS_KNOWLEDGE_URL`
> default). **Always set `THEMIS_KNOWLEDGE_ADDR=:8085`** when running them together.

> **Databases (5 on one PostgreSQL server):** `evidence`, `knowledge`, `governance`, `communication`, `bus`.
> Registry co-locates in the **`evidence`** database — Evidence validates a release id in-process via
> `registry.ReleaseExists`, so the registry tables must live there (point `cmd/registry` at the `evidence`
> DSN with `THEMIS_REGISTRY_MIGRATE=1`). The database boundary keeps contexts structurally isolated.
> See [`docs/engineering/PHASE3-STATUS.md`](docs/engineering/PHASE3-STATUS.md).

### Build & gate

```sh
go build ./...     # builds every service
make check         # build · test · lint · clean-arch · arch-test · coverage (+ integration) · deadcode
```

### 1. PostgreSQL — role and the five databases

```sh
psql -U postgres -c "CREATE USER themis WITH PASSWORD 'CHANGEME';"
for db in evidence knowledge governance communication bus; do
  psql -U postgres -c "CREATE DATABASE $db OWNER themis;"
done
```

Each service reads its options from the environment; every option is documented inline in
[`deploy/node.env.example`](deploy/node.env.example). Shared essentials (set for every persisting service):

```sh
export THEMIS_LOG_LEVEL=info          # debug | info | warn | error
export THEMIS_LOG_FORMAT=json         # json (prod) | console (dev)
export THEMIS_OTLP_LOGS_ENDPOINT=     # empty = console-only; e.g. otel-collector:4318 to export
# Per-service, THEMIS_DATABASE_DSN points at that service's OWN database; the four pipeline services
# additionally point THEMIS_BUS_DATABASE_DSN at the shared `bus` database (this is what wires end-to-end).
export PGBASE="postgres://themis:CHANGEME@localhost:5432"
export THEMIS_BUS_DATABASE_DSN="$PGBASE/bus?sslmode=disable"
```

### 2. Run the pipeline (start in this order)

Each service applies its own migrations (`*_MIGRATE=1`), serves under `/api/v1`, and runs its relay +
reader loops in the background. `THEMIS_BUS_MIGRATE=1` on the first service creates the `bus` `event_log`.
Run each in its own shell (or under systemd/tmux); `&` backgrounds them here for brevity.

```sh
# Registry — owns identity tables inside the `evidence` DB (Evidence reads them in-process).
# It shares that DB with Evidence, so it MUST keep its own migration-bookkeeping table
# (x-migrations-table); otherwise both services fight over the default `schema_migrations`
# and one silently skips its schema. (Tracked in docs/BACKLOG.md §C.)
THEMIS_DATABASE_DSN="$PGBASE/evidence?sslmode=disable&x-migrations-table=registry_schema_migrations" \
THEMIS_REGISTRY_MIGRATE=1 THEMIS_REGISTRY_ADDR=:8082 go run ./cmd/registry &

# Evidence — SBOM/VEX intake + inventory. Migrates its own tables AND the bus event_log.
THEMIS_DATABASE_DSN="$PGBASE/evidence?sslmode=disable" \
THEMIS_EVIDENCE_MIGRATE=1 THEMIS_BUS_MIGRATE=1 THEMIS_EVIDENCE_ADDR=:8081 go run ./cmd/evidence &

# Knowledge — correlates the SBOM's components against CVEs (reads Evidence inventory + OSV).
# NOTE the explicit :8085 — the code default :8082 collides with Registry.
THEMIS_DATABASE_DSN="$PGBASE/knowledge?sslmode=disable" \
THEMIS_EVIDENCE_URL=http://localhost:8081 \
THEMIS_KNOWLEDGE_MIGRATE=1 THEMIS_KNOWLEDGE_ADDR=:8085 go run ./cmd/knowledge &

# Governance — opens Findings, holds Positions. AI ON (uses the Intelligence Gateway below).
THEMIS_DATABASE_DSN="$PGBASE/governance?sslmode=disable" \
THEMIS_GOVERNANCE_AI_ENABLED=1 THEMIS_INTELLIGENCE_URL=http://localhost:8086 \
THEMIS_GOVERNANCE_MIGRATE=1 THEMIS_GOVERNANCE_ADDR=:8083 go run ./cmd/governance &

# Communication — materializes + publishes VEX/advisories (reads Positions from Governance).
THEMIS_DATABASE_DSN="$PGBASE/communication?sslmode=disable" \
THEMIS_GOVERNANCE_URL=http://localhost:8083 \
THEMIS_COMMUNICATION_MIGRATE=1 THEMIS_COMMUNICATION_ADDR=:8084 go run ./cmd/communication &
```

(`THEMIS_BUS_DATABASE_DSN` is exported once above, so all four pipeline services inherit it. Drop it — or
set `THEMIS_GOVERNANCE_AI_ENABLED=0` and skip the Intelligence service — for a bus-less / AI-less single
context.)

### 3. Drive an SBOM end-to-end

```sh
# Register identity → capture the release id. Every register endpoint returns {"id": ...}.
J='-s -H content-type:application/json'
PID=$(curl $J localhost:8082/api/v1/products -d '{"name":"acme"}'                            | jq -r .id)
JID=$(curl $J localhost:8082/api/v1/projects -d "{\"product_id\":\"$PID\",\"name\":\"api\"}" | jq -r .id)
RID=$(curl $J localhost:8082/api/v1/releases -d "{\"project_id\":\"$JID\",\"version\":\"1.0.0\"}" | jq -r .id)

# Upload an SBOM against that release (Evidence accepts CycloneDX/SPDX JSON in `document`).
curl $J localhost:8081/api/v1/evidence -d "$(jq -n --arg r "$RID" --rawfile d ./my-sbom.json \
  '{kind:"sbom",format:"cyclonedx",subject_release_id:$r,document:$d}')"

# Wait ~10s for the cascade (2s loops × Evidence→Knowledge→Governance hops), then watch a Finding appear:
curl -s "localhost:8083/api/v1/releases/$RID/posture" | jq .   # → grab the finding_id, set FID below
FID=<FINDING_ID>

# (optional) Ask cyberpal for an advisory recommendation on a Finding (records a proposal; never decides):
curl $J -X POST "localhost:8083/api/v1/findings/$FID/recommend" | jq .

# Decide the Position (human): raise an "affected" proposal and accept it.
PROP=$(curl $J "localhost:8083/api/v1/findings/$FID/proposals" \
  -d '{"stance":"affected","proposer_kind":"human","proposer_id":"you"}' | jq -r .proposal_id)
curl $J -X POST "localhost:8083/api/v1/findings/$FID/proposals/$PROP/accept" \
  -d '{"actor_id":"you","actor_kind":"human"}'

# Publish OpenVEX (human-triggered), wait ~4s, then read the artifact — it names the CVE.
curl $J localhost:8084/api/v1/publications \
  -d "{\"finding_id\":\"$FID\",\"artifact_type\":\"vex\",\"format\":\"openvex\"}"
curl -s "localhost:8084/api/v1/publications?release=$RID" | jq .
```

> **Quick smoke without the Registry.** To skip identity registration, start Evidence with
> `THEMIS_EVIDENCE_KNOWN_RELEASES=rel-demo` (a dev stub SubjectRef) and upload with
> `subject_release_id:"rel-demo"`. This is what the `make e2e-pipeline` black-box proof uses.

### 4. Intelligence Gateway (optional AI — Ollama)

`cmd/intelligence` is **stateless** (no database) and part of the **optional AI plane** — the pipeline is
fully correct with it off (disabled ≡ unavailable). It is **on-demand and advisory**: a human POSTs
`/api/v1/findings/{id}/recommend` to Governance, which invokes the Gateway's `recommend_position`
capability (grounded via the Governance + Knowledge read APIs), and the Gateway returns a recommendation
that Governance records as a **proposal a human still accepts or rejects**. It never runs automatically in
the pipeline and never decides.

**Provider** (config-selected):

- **Ollama (real, local-first — the default):** leave `THEMIS_INTELLIGENCE_PROVIDER` empty. Point
  `THEMIS_OLLAMA_URL` at the Ollama server (default `http://localhost:11434`) and pin
  `THEMIS_INTELLIGENCE_MODEL` to the exact tag from `ollama list` (e.g. your `cyberpal` model).
- **Fake (no model):** `THEMIS_INTELLIGENCE_PROVIDER=fake` — deterministic, for wiring/smoke tests.

```sh
ollama serve &                 # on a Linux GPU host, ensure the CUDA/ROCm runtime is present
ollama pull cyberpal           # or whatever you named it; confirm the tag with `ollama list`

THEMIS_GOVERNANCE_URL=http://localhost:8083 \
THEMIS_KNOWLEDGE_URL=http://localhost:8085 \
THEMIS_OLLAMA_URL=http://localhost:11434 \
THEMIS_INTELLIGENCE_MODEL=cyberpal \
THEMIS_INTELLIGENCE_ADDR=:8086 go run ./cmd/intelligence &   # grounds via Governance + Knowledge
```

Ollama's OpenAI-compatible endpoint uses `json_object` structured output by default
(`THEMIS_LLM_RESPONSE_FORMAT` empty). If your model needs a bearer token or JSON-schema mode, set
`THEMIS_LLM_API_KEY` / `THEMIS_LLM_RESPONSE_FORMAT=json_schema` (see [TESTING.md](TESTING.md) and
`make e2e-llm`).

**The disable gate (D13)** is one wiring choice on the *Governance* service — no call-site flags:

```sh
# AI OFF (default): don't run cmd/intelligence; leave the flag unset → Governance wires a no-op advisor.
# AI ON (as in the runbook above):
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
