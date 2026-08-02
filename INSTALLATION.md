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
| Go | 1.25+ | Must match `go` in `go.mod`; also the floor for golangci-lint (below) |
| PostgreSQL | 14+ (16 recommended) | Running and reachable before you start Themis |
| jq | any | Only for the SBOM walkthrough's `curl` helpers in Part A |
| golangci-lint | **v2.x**, built with Go ≥ 1.25 | Only for `make check` / `make lint` (contributing/CI) — **not** needed to run Themis |

The binaries need no runtime dependency beyond PostgreSQL. The Intelligence Gateway additionally needs a
model runtime **only when AI is enabled** (Ollama — see the Intelligence Gateway step in Part A below).

**Installing golangci-lint (only if you run `make check` / `make lint`).** The repo's `.golangci.yml` is
`version: "2"`, so a v1 binary can't parse it — you need **v2**. Install the latest v2 the same way CI
does; the latest build tracks the current Go toolchain, so it supports this project's **Go 1.25** — an
older golangci-lint built against an older Go will refuse to typecheck 1.25 code. Running Themis needs none
of this (`go build ./...` + the services); this is the dev/CI quality gate only.

```sh
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b "$(go env GOPATH)/bin"
export PATH="$(go env GOPATH)/bin:$PATH"   # add to your shell profile to persist
golangci-lint version                       # expect 2.x, built with go1.25+
```

---

## Part A — Phase-3 greenfield services

The pipeline is **Evidence → Knowledge → Governance → Communication**, over a **Registry/Kernel**
foundation, with a supporting **Intelligence Gateway** beside it. Each is its own binary and **its own
database**, and since **M5** they collaborate over a real **event bus** (a dedicated `bus` PostgreSQL
database holding one `event_log`) plus read-only HTTP APIs — no shared business tables.

| Service | Command | Port | Own database | Reads over HTTP | Migrate on startup |
| ------- | ------- | ---- | ------------ | --------------- | ------------------ |
| Registry | `cmd/registry` | `:8082` | `evidence` (shared) | — | `psql` schema load (step 4) |
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
> `registry.ReleaseExists`, so the registry tables must live there (its schema is loaded with `psql`, not
> self-migrated — see step 4). The database boundary keeps contexts structurally isolated.
> See [`docs/engineering/PHASE3-STATUS.md`](docs/engineering/PHASE3-STATUS.md).

### 1. Install and start PostgreSQL

The greenfield services need a running PostgreSQL (unlike `make check`, which provisions its own throwaway
embedded Postgres). On a fresh Linux box:

```sh
# Debian / Ubuntu
sudo apt-get update && sudo apt-get install -y postgresql
sudo systemctl enable --now postgresql

# RHEL / Fedora / Rocky
sudo dnf install -y postgresql-server && sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql
```

Create the `themis` role and the **six** databases (as the `postgres` superuser): the four pipeline
databases (`evidence` — which also co-locates the Registry identity schema — `knowledge`, `governance`,
`communication`), the shared `bus` event log, and `auth` (the API-key store for inbound edge auth, F1). Set
the password **once** in a shell variable and reuse it everywhere — the runbook's DSNs read the same `$PGPW`,
so there is no second place to keep in sync:

```sh
# Use only letters/digits — @ : / # ' $ would break the connection URL. Keep this exported for later steps.
export PGPW='ChangeMe4Themis'

sudo -u postgres psql -c "CREATE USER themis WITH PASSWORD '$PGPW';"
for db in evidence knowledge governance communication bus auth; do
  sudo -u postgres psql -c "CREATE DATABASE $db OWNER themis;"
done
# verify the themis role can connect over TCP (default localhost auth is password-based; prints '1'):
psql "postgres://themis:$PGPW@localhost:5432/evidence?sslmode=disable" -c 'SELECT 1;'
```

Each database is owned by `themis` on purpose: on PostgreSQL 15+ only the database owner may create tables
in the `public` schema, and the per-context migrations need that — owning the DB covers it, no extra GRANT.
Creating the databases needs the `postgres` superuser (`sudo -u postgres`) because the `themis` role has no
`CREATEDB`; everything *inside* a database (migrations, the runbook) uses the plain `themis` DSN.

> **Re-testing from a clean slate?** If these databases already exist from a previous run, **stop every
> service first** — an open connection blocks `DROP DATABASE` — then drop and recreate in one shot:
>
> ```sh
> sudo systemctl stop 'themis@*' 2>/dev/null   # if running under systemd (step 7)
> pkill -f 'bin/(registry|evidence|knowledge|governance|communication|intelligence)' 2>/dev/null
> for db in evidence knowledge governance communication bus auth; do
>   sudo -u postgres psql -c "DROP DATABASE IF EXISTS $db WITH (FORCE);" -c "CREATE DATABASE $db OWNER themis;"
> done
> ```
>
> `WITH (FORCE)` (PostgreSQL 13+) terminates any lingering connection so the drop cannot hang.

### 2. Build the services

```sh
go build ./...     # compile-check everything (silent output = success)
# then produce the service binaries the runbook runs (cleaner than `go run` for six background processes):
go build -o bin/ ./cmd/registry ./cmd/evidence ./cmd/knowledge ./cmd/governance ./cmd/communication ./cmd/intelligence
ls bin/            # registry evidence knowledge governance communication intelligence
```

`make build` builds only the frozen v0.3.x monolith (→ `./bin/themis`) — you don't need it for the
pipeline. `make check` / `make lint` are the **contributor/CI quality gate** (lint · clean-arch · arch-test
· coverage · deadcode; the coverage step spins up its own embedded Postgres). They are **not** part of
deploying — skip them here, and run them only when contributing, after installing golangci-lint v2
(see [Prerequisites](#prerequisites)).

### 3. Configure the shared environment

Each service reads its options from the environment; every option is documented inline in
[`deploy/node.env.example`](deploy/node.env.example). Set these once (they apply to every persisting
service in the runbook below):

```sh
export THEMIS_LOG_LEVEL=info          # debug | info | warn | error
export THEMIS_LOG_FORMAT=json         # json (prod) | console (dev)
export THEMIS_OTLP_LOGS_ENDPOINT=     # empty = console-only; e.g. otel-collector:4318 to export
# Per-service, THEMIS_DATABASE_DSN points at that service's OWN database; the four pipeline services
# additionally point THEMIS_BUS_DATABASE_DSN at the shared `bus` database (this is what wires end-to-end).
export PGBASE="postgres://themis:$PGPW@localhost:5432"   # $PGPW from step 1 — re-export it in a new shell
export THEMIS_BUS_DATABASE_DSN="$PGBASE/bus?sslmode=disable"
```

### 4. Run the pipeline (start in this order)

Each service serves under `/api/v1` and runs its relay + reader loops in the background; the ones with
`*_MIGRATE=1` apply their own migrations on startup, and `THEMIS_BUS_MIGRATE=1` on Evidence creates the
shared `bus` event_log. Logs go to `logs/`.

**Registry first — load its schema by hand.** Registry co-locates its identity tables in the `evidence`
database (Evidence reads them in-process), but it cannot self-migrate there: golang-migrate's single default
`schema_migrations` table would clash with Evidence's, and passing `x-migrations-table` on the DSN to work
around that **breaks the running service** — pgx forwards the unknown parameter to Postgres and every
connection is rejected. Instead load the schema directly (the migrations are idempotent
`CREATE TABLE IF NOT EXISTS`) and run Registry with a plain DSN and **no** migrate flag. Load **both**
migrations — `000001` is the Product→Project→Release identity, `000002` is the enterprise **estate** graph
(Customer / Microservice / Deployment) that the release blast-radius traversal needs (C1/C2); skip the second
and `GET /releases/{id}/blast-radius` returns an empty estate and the priority multiplier stays at 1.0×:

```sh
psql "$PGBASE/evidence?sslmode=disable" -f internal/registry/adapters/store/migrations/000001_registry.up.sql
psql "$PGBASE/evidence?sslmode=disable" -f internal/registry/adapters/store/migrations/000002_estate.up.sql
```

```sh
mkdir -p logs

# Registry — plain DSN, no migrate (schema loaded above).
THEMIS_DATABASE_DSN="$PGBASE/evidence?sslmode=disable" THEMIS_REGISTRY_ADDR=:8082 \
  ./bin/registry > logs/registry.log 2>&1 &

# Evidence — SBOM/VEX intake + inventory. Migrates its own tables AND the bus event_log.
THEMIS_DATABASE_DSN="$PGBASE/evidence?sslmode=disable" \
THEMIS_EVIDENCE_MIGRATE=1 THEMIS_BUS_MIGRATE=1 THEMIS_EVIDENCE_ADDR=:8081 \
  ./bin/evidence > logs/evidence.log 2>&1 &

# Knowledge — correlates the SBOM's components against CVEs (reads Evidence inventory + OSV).
# NOTE the explicit :8085 — the code default :8082 collides with Registry.
THEMIS_DATABASE_DSN="$PGBASE/knowledge?sslmode=disable" \
THEMIS_EVIDENCE_URL=http://localhost:8081 \
THEMIS_KNOWLEDGE_MIGRATE=1 THEMIS_KNOWLEDGE_ADDR=:8085 \
  ./bin/knowledge > logs/knowledge.log 2>&1 &

# Governance — opens Findings, holds Positions. AI ON (calls Intelligence at :8086 only on /recommend).
THEMIS_DATABASE_DSN="$PGBASE/governance?sslmode=disable" \
THEMIS_GOVERNANCE_AI_ENABLED=1 THEMIS_INTELLIGENCE_URL=http://localhost:8086 \
THEMIS_GOVERNANCE_MIGRATE=1 THEMIS_GOVERNANCE_ADDR=:8083 \
  ./bin/governance > logs/governance.log 2>&1 &

# Communication — materializes + publishes VEX/advisories (reads Positions from Governance).
THEMIS_DATABASE_DSN="$PGBASE/communication?sslmode=disable" \
THEMIS_GOVERNANCE_URL=http://localhost:8083 \
THEMIS_COMMUNICATION_MIGRATE=1 THEMIS_COMMUNICATION_ADDR=:8084 \
  ./bin/communication > logs/communication.log 2>&1 &

sleep 6
ss -ltn 'sport = :8081 or sport = :8082 or sport = :8083 or sport = :8084 or sport = :8085'   # 5× LISTEN
grep -iRE "listening|event bus connected|reader enabled|error|abort|panic" logs/
```

(`THEMIS_BUS_DATABASE_DSN` is exported once above, so all four pipeline services inherit it. Drop it — or
set `THEMIS_GOVERNANCE_AI_ENABLED=0` and skip the Intelligence service — for a bus-less / AI-less single
context.)

> **Restarting a service** (e.g. after a rebuild): `pkill -f 'bin/<service>'` then start it again. If your
> shell has `noclobber` set, `>` refuses to overwrite an existing log file — use `>|` on restarts. For
> anything beyond a quick trial, run the services under **systemd** instead (step 7) — that is the durable
> way to manage lifecycle, and it sidesteps this entirely.

### 4a. Enable inbound edge auth (optional — F1)

By default the runbook above runs **open** (no API key) — fine on a trusted single box. To require an
`X-API-Key` on every node's `/api/v1`, point each node at the shared `auth` database and mint a key. Auth is
**inbound-edge only**: it guards external callers, not service-to-service reads (those clients send no key).

```sh
export THEMIS_AUTH_DATABASE_DSN="$PGBASE/auth?sslmode=disable"

# Mint an admin key (read+write). THEMIS_AUTH_MIGRATE=1 creates the api_keys table on first run.
# The token is printed ONCE — copy it now; only its bcrypt hash is stored. Run from the repo root
# (the migrations path is relative). Scopes: admin (read+write) | read (read-only).
THEMIS_AUTH_MIGRATE=1 go run ./cmd/authadmin create-key --name ci --scopes admin
# → prints: key-<uuid>  <TOKEN>          # export it: export THEMIS_API_KEY=<TOKEN>
```

Then **restart the nodes with `THEMIS_AUTH_DATABASE_DSN` exported** (it is inherited by every service you
start in that shell). Each node logs `AUTH ENABLED` on boot; without the DSN it logs `AUTH DISABLED`. Set
`THEMIS_AUTH_REQUIRED=1` in production so a node **refuses to start** if the DSN is empty (it can never boot
open by mistake). Callers then pass the token:

```sh
curl -H "X-API-Key: $THEMIS_API_KEY" http://localhost:8081/api/v1/...     # 200; without the header → 401
```

> **Gotcha we hit:** exporting `THEMIS_AUTH_DATABASE_DSN` in the *same shell* where you later start the
> pipeline turns auth **on for every service**, and the plain `gf-upload-sbom.sh` driver sends no key → every
> registration returns **401**. For an open end-to-end run, keep auth in its own shell (or `unset
> THEMIS_AUTH_DATABASE_DSN` before step 5); prove auth separately as an edge spot-check.

### 4b. Enable enrichment feeds (optional)

Correlation always runs the **OSV** query-by-package source (language + distro ecosystems) — no config needed.
Every other feed is **opt-in and relevance-bounded**: each enriches only the CVEs already carded from your
SBOMs (EDR-KNOWLEDGE-01 D5), so none of them mirrors a full feed. They all run on the **Knowledge** node — set
the env below and (re)start `./bin/knowledge`.

```sh
# --- authoritative severity / CVSS (NVD) ---
THEMIS_NVD_ENABLED=1                 # scheduled modified-since watch → authoritative CVSS/severity on carded CVEs
THEMIS_NVD_DISCOVERY=1               # add NVD to correlation discovery (per-component CPE-gated keyword query)
THEMIS_NVD_API_KEY=<key>             # strongly recommended — NVD throttles hard without one
THEMIS_NVD_POLL_INTERVAL=6h

# --- exploit signals ---
THEMIS_EPSSKEV_ENABLED=1             # EPSS + CISA KEV + ExploitDB → carded CVEs

# --- vendor VEX (the EDR-VEX-01 cluster) ---
THEMIS_REDHAT_ENABLED=1              # Red Hat per-CVE feed: vendor severity + not_affected + fixed verdict; covers RHEL/Rocky/Alma
THEMIS_REDHAT_POLL_INTERVAL=12h
THEMIS_VEXFEED_ENABLED=1             # generic CSAF-VEX feed (B4)
THEMIS_VEXFEED_URLS=https://<vendor>/csaf/vex,https://<vendor2>/...   # comma-separated CSAF trusted-provider bases
THEMIS_VEXFEED_POLL_INTERVAL=12h

# --- (Governance) blast-radius saturation cap, parity with the legacy config ---
THEMIS_BLAST_RADIUS_CAP=10           # unique-customer count at which the priority multiplier saturates to 2.0×
```

Example — restart Knowledge with NVD + Red Hat enabled. Discovery is **keyless-safe now** because discovery
I/O runs *outside* the inbox transaction (the D7 fix), so a slow feed no longer stalls the pipeline:

```sh
pkill -f 'bin/knowledge'
THEMIS_DATABASE_DSN="$PGBASE/knowledge?sslmode=disable" \
THEMIS_EVIDENCE_URL=http://localhost:8081 THEMIS_KNOWLEDGE_ADDR=:8085 \
THEMIS_NVD_ENABLED=1 THEMIS_NVD_API_KEY=<key> THEMIS_REDHAT_ENABLED=1 \
  ./bin/knowledge >| logs/knowledge.log 2>&1 &
```

Check feed health (B1) after a poll has run — each enabled feed reports `healthy` with its intelligence tier:

```sh
curl -s localhost:8085/api/v1/feeds | jq .    # nvd (tier 1), redhat (tier 2), vexfeed (tier 3), epsskev (tier 1) …
```

> The **first NVD poll is an up-to-120-day modified-since query (~12 min)**, so `nvd` health surfaces only
> after it completes. The Red Hat and CSAF-VEX feeds fetch **per carded CVE**, so their sweep time scales with
> your card set, not the vendor's whole catalog.

### 5. Drive an SBOM end-to-end

```sh
J='-s -H content-type:application/json'

# Easiest — the greenfield helper registers Product -> Project -> Release and uploads the SBOM. It
# auto-detects CycloneDX/SPDX and STREAMS the body from a file, so large SBOMs work (see note below):
./scripts/gf-upload-sbom.sh -f ./my-sbom.json -p acme -j api -v 1.0.0
export RID=<the RELEASE_ID it prints>          # reuse an existing release with:  -r <RELEASE_ID>

# --- or drive the raw API yourself (each register endpoint returns {"id": ...}): ---
# PID=$(curl $J localhost:8082/api/v1/products -d '{"name":"acme"}'                            | jq -r .id)
# JID=$(curl $J localhost:8082/api/v1/projects -d "{\"product_id\":\"$PID\",\"name\":\"api\"}" | jq -r .id)
# export RID=$(curl $J localhost:8082/api/v1/releases -d "{\"project_id\":\"$JID\",\"version\":\"1.0.0\"}" | jq -r .id)
# Upload — inline -d only works for SMALL SBOMs: a single argv is capped at 128KB on Linux
# (MAX_ARG_STRLEN), so a large document fails with "Argument list too long". For anything sizeable,
# build the body into a file and stream it (what the helper above does):
#   tmp=$(mktemp); jq -n --arg r "$RID" --rawfile d ./my-sbom.json \
#     '{kind:"sbom",format:"cyclonedx",subject_release_id:$r,document:$d}' > "$tmp"
#   curl $J localhost:8081/api/v1/evidence --data-binary @"$tmp"; rm -f "$tmp"

# Wait ~10s for the cascade (2s loops × Evidence→Knowledge→Governance hops), then watch a Finding appear:
curl -s "localhost:8083/api/v1/releases/$RID/posture" | jq .   # → grab the finding_id, set FID below
FID=<FINDING_ID>

# (optional) Ask cyberpal for an advisory recommendation on a Finding (records a proposal; never decides).
# Requires the Intelligence Gateway (step 6) already running; without it this returns 204 (no recommendation).
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

> **If no Finding appears — verify the cascade.** The pipeline is event-driven, so a stuck Finding almost
> always means events did not cross a context. Check, in order:
>
> ```sh
> # 1. Did Evidence publish, and did each reader advance its cursor to match?
> psql "$PGBASE/bus?sslmode=disable" -c "SELECT source_context, max(seq) FROM event_log GROUP BY 1;"
> psql "$PGBASE/bus?sslmode=disable" -c "SELECT consumer, source_context, last_seq FROM stream_cursor ORDER BY 1;"
> # 2. Did Knowledge correlate (cards + matches > 0)?
> psql "$PGBASE/knowledge?sslmode=disable" -c "SELECT (SELECT count(*) FROM faultlines) cards, (SELECT count(*) FROM faultline_matches) matches;"
> # 3. Nothing should be stuck 'idle in transaction' — a long-open write tx would stall every reader:
> psql "$PGBASE/postgres?sslmode=disable" -c "SELECT pid, state, now()-xact_start age, left(query,50) FROM pg_stat_activity WHERE state LIKE 'idle in transaction%';"
> ```
>
> A `stream_cursor` that lags `event_log`'s max `seq` for a source means that reader is not draining. Query 3
> is the smoking gun for the historical correlation-transaction stall (fixed 2026-08-01: discovery I/O now
> runs outside the inbox transaction, so a healthy pipeline shows **no** long-lived `idle in transaction`
> row). `grep -i "error\|halt\|panic" logs/*.log` surfaces a poison-halted stream.

> **No AI required — this is the whole pipeline.** Every step above runs with the AI plane OFF.
> The optional `recommend` call (and step 6) is the *only* AI touchpoint; the Position is decided
> by the human `proposals` + `accept` calls, so you can go all the way from a registered release to
> a published OpenVEX artifact without ever starting the Intelligence Gateway. `make e2e-pipeline`
> runs exactly this **register → upload SBOM → correlate → Finding → Position → OpenVEX** flow
> deterministically (no model, self-provisioned Postgres) and asserts the artifact names the CVE —
> it is the CI gate that guards this flow on every PR.
>
> **Quick smoke without the Registry.** For a throwaway dev run you can skip identity registration:
> start Evidence with `THEMIS_EVIDENCE_KNOWN_RELEASES=rel-demo` (a dev stub SubjectRef) and upload
> with `subject_release_id:"rel-demo"`.

### 5a. Test vendor-VEX suppression + the fixed verdict (EDR-VEX-01)

A vendor `not_affected` statement (uploaded or from a feed) never silently drops a Finding — it becomes a
**governed proposal** a human or policy accepts. Two ways to exercise it:

**(a) Upload a VEX and suppress a Finding.** With a Finding open for `$FID` (from step 5), upload an OpenVEX
`not_affected` for its CVE + package, then watch it flow Knowledge → Governance:

```sh
CVE=<the finding's CVE>          # from: curl -s localhost:8083/api/v1/releases/$RID/posture | jq -r '.[0].cve'
tmp=/tmp/vex.json; rm -f "$tmp"  # noclobber-safe: delete then recreate
jq -n --arg r "$RID" --arg cve "$CVE" '{kind:"vex",format:"openvex",subject_release_id:$r,document:(
  {"@context":"https://openvex.dev/ns/v0.2.0","@id":"vex-1","author":"acme","timestamp":"2024-01-15T00:00:00Z",
   statements:[{vulnerability:{name:$cve},products:[{"@id":"pkg:rpm/rhel/openssl"}],
                status:"not_affected",justification:"vulnerable_code_not_present"}]} | tostring)}' > "$tmp"
curl $J localhost:8081/api/v1/evidence --data-binary @"$tmp"; rm -f "$tmp"

sleep 8
# 1. The card now carries the vendor statement (Knowledge read API, :8085; getFaultlineByCVE returns one card):
curl -s "localhost:8085/api/v1/faultlines?cve=$CVE" | jq '.applicabilities'
# 2. Governance raised a SYSTEM not_affected proposal — accept it (a human decision). The proposal id
#    embeds the package PURL (contains a '/'), so URL-encode it or the accept PATH 404s (BACKLOG: path-safe ids):
PROP=$(curl -s "localhost:8083/api/v1/findings/$FID" | jq -r '.proposals[] | select(.stance=="not_affected") | .id' | head -1)
PROP_ENC=$(printf '%s' "$PROP" | jq -sRr @uri)
curl $J -X POST "localhost:8083/api/v1/findings/$FID/proposals/$PROP_ENC/accept" -d '{"actor_id":"you","actor_kind":"human"}'
# 3. The Finding's Position is now not_affected (has_position=true, stance=not_affected) — it is DISPOSITIONED,
#    not dropped: effective_priority stays the intrinsic base×blast, so filter the posture BY STANCE to exclude
#    suppressed findings (BACKLOG: effective_priority ignoring stance).
curl -s "localhost:8083/api/v1/releases/$RID/posture" | jq '.[] | {cve, stance, has_position, effective_priority}'
```

**(b) Let a feed do it.** With `THEMIS_REDHAT_ENABLED=1` (or the CSAF-VEX feed, §4b), the same applicability
Proposal is folded **automatically** for any carded CVE Red Hat marks `not_affected` — no upload. And the
**fixed verdict** needs no action at all: if a `pkg:rpm/...` component is already at/above its same-EL-stream
Red Hat fix, correlation records **no match**, so no Finding is ever opened for that (already-patched)
occurrence. A cross-stream fix (an el9 fix vs an el8 install) is never applied — so a live vuln is never hidden.

### 6. Intelligence Gateway (optional AI — Ollama)

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

### 7. Run as systemd services (survive logout / reboot)

Steps 4–6 run the services as background jobs of your shell — fine for a trial, but they die when the shell
exits. To install them as managed **systemd** services (auto-start on boot, restart on failure, logs in
journald), use the installer under [`deploy/systemd/`](deploy/systemd). Build the binaries (step 2), make
sure the databases exist (step 1), then stop any hand-started copies so they don't hold the ports:

```sh
# from the repo root, as root, with the DB password (and your Ollama model tag):
pkill -f 'bin/(registry|evidence|knowledge|governance|communication|intelligence)' || true
sudo THEMIS_PGPW='<db-password>' THEMIS_INTELLIGENCE_MODEL='<ollama-model:tag>' \
  ./deploy/systemd/install-systemd.sh
```

It loads the registry schema (idempotent), writes one `EnvironmentFile` per service under `/etc/themis/`
(mode 0640), installs a single templated `themis@.service`, and enables + starts
`themis@{registry,evidence,knowledge,governance,communication,intelligence}`. Manage them the usual way:

```sh
systemctl status 'themis@*'                 # all six
sudo systemctl restart themis@knowledge     # e.g. after a rebuild
journalctl -u themis@knowledge -f           # follow logs
```

To change configuration, edit `/etc/themis/<service>.env` then `sudo systemctl restart themis@<service>`.
`WorkingDirectory` is the repo root (services resolve their migrations by a relative path), so keep the
built `bin/` in place.

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
