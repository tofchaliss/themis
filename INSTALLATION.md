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

## Quick runbooks (a Linux VM under systemd)

Three paste-safe runbooks for the usual jobs on a VM. Every block is bash, every comment starts
with `#`, and every step ends with what you should see. Part A below explains each step in depth;
read it when a step fails or you need a setting these runbooks leave at its default.

| Job | Runbook |
| --- | --- |
| Empty VM to a running stack, auth on | [R1. Fresh install](#r1-fresh-install) |
| Stop and start, nothing else changes | [R2. Restart](#r2-restart-an-existing-setup) |
| New code from `main` onto a running stack | [R3. Pull the latest code and restart](#r3-pull-the-latest-code-and-restart) |

### R1. Fresh install

From an empty Linux VM to all seven nodes running with auth on. Run every block as your normal
user. Needs Go 1.25+, git, jq and PostgreSQL 14+.

**Step 1. Tools and code.**

```bash
# RHEL / Rocky. On Ubuntu use: sudo apt-get install -y git jq postgresql
sudo dnf install -y git jq postgresql-server
sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql
go version
# expect go1.25 or newer
sudo mkdir -p /opt/themis/src && sudo chown "$USER" /opt/themis/src
git clone https://github.com/tofchaliss/themis.git /opt/themis/src/themis
cd /opt/themis/src/themis
```

**Step 2. Database password, role and databases.** The password is generated, never typed, and
saved to a file only you can read, because nothing else prints it again (Part A step 1).

```bash
( umask 077; LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 24 > ~/.themis-pg.pw )
export PGPW=$(cat ~/.themis-pg.pw)
export PGBASE="postgres://themis:$PGPW@localhost:5432"
sudo -u postgres psql -c "CREATE USER themis WITH PASSWORD '$PGPW';"
for db in evidence knowledge governance communication bus auth intelligence; do sudo -u postgres psql -c "CREATE DATABASE $db OWNER themis;"; done
psql "$PGBASE/evidence?sslmode=disable" -tAc 'SELECT 1;'
# expect: 1
```

If `SELECT 1` fails with `Ident authentication failed`, PostgreSQL is not using passwords on
localhost: change `ident` to `scram-sha-256` on the `127.0.0.1` and `::1` lines of `pg_hba.conf`,
then `sudo systemctl reload postgresql`.

**Step 3. Build.** The cache paths stop a bad profile setting from breaking the build.

```bash
cd /opt/themis/src/themis
env GOCACHE=$HOME/.cache/go-build GOMODCACHE=$HOME/go/pkg/mod go build -o bin/ ./cmd/... && echo BUILD-OK
ls bin/
# expect: registry evidence knowledge governance communication intelligence dashboard authadmin, among others
```

**Step 4. Install the systemd services** (Part A step 7). This writes `/etc/themis/<node>.env`
and starts all seven nodes with auth OFF. Set the model to your Ollama model's tag.

```bash
cd /opt/themis/src/themis
sudo THEMIS_PGPW="$PGPW" THEMIS_INTELLIGENCE_MODEL='cyberpal20b:latest' ./deploy/systemd/install-systemd.sh
systemctl is-active themis@registry themis@evidence themis@knowledge themis@governance themis@communication themis@intelligence themis@dashboard
# expect: active, seven times
```

**Step 5. Mint the keys** (Part A step 4a-bis). One key per calling node with the smallest scope
it needs, plus your own admin key. Each key goes straight into a file and never onto the screen.

```bash
cd /opt/themis/src/themis
export THEMIS_AUTH_DATABASE_DSN="$PGBASE/auth?sslmode=disable"
export THEMIS_AUTH_MIGRATE=1
mint() { ./bin/authadmin create-key --name "$1" --scopes "$2" | awk '/shown once/{getline; getline; print $1}'; }
mkdir -p ~/.themis-keys && chmod 700 ~/.themis-keys
( umask 077; mint knowledge-node read > ~/.themis-keys/knowledge; mint governance-node admin > ~/.themis-keys/governance; mint communication-node read > ~/.themis-keys/communication; mint intelligence-node read > ~/.themis-keys/intelligence; mint dashboard admin > ~/.themis-keys/dashboard; mint operator admin > ~/.themis-keys/operator )
wc -c ~/.themis-keys/*
# expect: six files, none of them 0 bytes
unset THEMIS_AUTH_MIGRATE
```

**Step 6. Switch auth on for every node.** Two halves: every node checks incoming keys, and every
calling node sends its own key. Doing only the first half silently breaks the pipeline.

```bash
for n in registry evidence knowledge governance communication intelligence dashboard; do printf 'THEMIS_AUTH_DATABASE_DSN=%s\nTHEMIS_AUTH_REQUIRED=1\n' "$THEMIS_AUTH_DATABASE_DSN" | sudo tee -a /etc/themis/$n.env > /dev/null; done
for n in knowledge governance communication intelligence dashboard; do printf 'THEMIS_API_KEY=%s\n' "$(cat ~/.themis-keys/$n)" | sudo tee -a /etc/themis/$n.env > /dev/null; done
sudo systemctl restart 'themis@*'
sleep 5
sudo journalctl -u 'themis@*' --since '-1 min' --no-pager | grep -cE 'API-key auth enabled'
# expect: 6 (the dashboard logs its sign-in setup instead)
```

**Step 7. Check end to end.** Run `vm-verify`, then sign in to the GUI at `http://<vm-host>:8090`
as `admin` / `Themis@123` and change that password in the Admin tab right away (Part A step 6a).

```bash
cd /opt/themis/src/themis
env THEMIS_API_KEY=$(cat ~/.themis-keys/operator) ./scripts/vm-verify.sh
# expect: every reader at 0 pending and "no issues found"
```

The last proof is a real SBOM: it shows the nodes can call each other with their keys.

```bash
cd /opt/themis/src/themis
rm -f ~/smoke-sbom.json
printf '%s\n' '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","name":"log4j-core","group":"org.apache.logging.log4j","version":"2.14.1","purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]}' > ~/smoke-sbom.json
env THEMIS_API_KEY=$(cat ~/.themis-keys/operator) ./scripts/gf-upload-sbom.sh -f ~/smoke-sbom.json -p smoke -j smoke-core -v 1.0.0 -c
# expect: RELEASE_ID=... and, about a minute later, Log4Shell findings for that release in the GUI
```

### R2. Restart an existing setup

No new code and no config change. The start order does not matter: each node resumes its event
stream where it stopped. After a VM reboot nothing is needed; the units are enabled and start on
their own.

```bash
sudo systemctl restart 'themis@*'
sleep 5
systemctl is-active themis@registry themis@evidence themis@knowledge themis@governance themis@communication themis@intelligence themis@dashboard
# expect: active, seven times
```

One node only, for example after editing its env file:

```bash
sudo systemctl restart themis@knowledge
sudo journalctl -u themis@knowledge -n 30 --no-pager
```

Check it is healthy. The database address is read from the evidence node's own env file, so this
works on any install.

```bash
cd /opt/themis/src/themis
export PGBASE=$(sudo grep -h '^THEMIS_DATABASE_DSN=' /etc/themis/evidence.env | cut -d= -f2- | sed 's|/evidence?.*||')
export THEMIS_API_KEY=$(cat ~/.themis-keys/operator)
./scripts/vm-verify.sh
# expect: every reader at 0 pending and "no issues found"
unset THEMIS_API_KEY
```

If a node shows `failed`, read why with `sudo journalctl -u themis@<node> -n 50 --no-pager`:

- `password authentication failed`: the password in `/etc/themis/*.env` no longer matches the
  `themis` role (Part A step 7 shows how to rewrite them all).
- `address already in use`: a hand-started copy holds the port. Stop it with `pkill -f bin/<node>`
  and restart.
- `HALTED`: an event stream is stuck on one event, and a restart does not clear it (see
  [step 8](#8-upgrade-an-existing-deployment-pull-build-restart)).

### R3. Pull the latest code and restart

New code from `main` onto a running setup; data and keys stay. Each node migrates its own
database when it starts, so there is no separate migrate step. Re-running the installer does not
update existing env files, which is why step 4 exists.

**Step 1. Look before you change anything.** Read-only.

```bash
cd /opt/themis/src/themis
git status -sb | head -1
# expect: ## main...origin/main
git status --short | head
# expect: nothing; local edits would block the pull
sudo journalctl -u 'themis@*' --since '-7 days' --no-pager | grep -i 'HALTED' | tail -3
# expect: nothing; a HALTED stream stays stuck after the upgrade too (step 8)
```

**Step 2. Pull `main`.** The first line saves where you were, for going back.

```bash
cd /opt/themis/src/themis
git rev-parse HEAD > ~/.themis-last-good
git fetch origin && git checkout main && git pull --ff-only origin main
git log --oneline -3
```

**Step 3. Build.** The `&&` stops here if the build fails, so the restart never runs the old
binaries by mistake.

```bash
cd /opt/themis/src/themis
env GOCACHE=$HOME/.cache/go-build GOMODCACHE=$HOME/go/pkg/mod go build -o bin/ ./cmd/... && echo BUILD-OK
# expect: BUILD-OK
```

**Step 4. Add settings introduced since your install.** Check the merged PRs for new env lines.
These two are safe to run every time: each adds its line only when it is missing. The env files
are root-only, so the check needs `sudo` too.

```bash
sudo grep -q '^THEMIS_DASHBOARD_MIGRATE=' /etc/themis/dashboard.env || echo 'THEMIS_DASHBOARD_MIGRATE=1' | sudo tee -a /etc/themis/dashboard.env
sudo grep -q '^THEMIS_KNOWLEDGE_URL=' /etc/themis/evidence.env || printf 'THEMIS_KNOWLEDGE_URL=http://localhost:8085\nTHEMIS_GOVERNANCE_URL=http://localhost:8083\n' | sudo tee -a /etc/themis/evidence.env
```

**Step 5. Restart and check.**

```bash
cd /opt/themis/src/themis
sudo systemctl restart 'themis@*'
sleep 10
systemctl is-active themis@registry themis@evidence themis@knowledge themis@governance themis@communication themis@intelligence themis@dashboard
# expect: active, seven times
export PGBASE=$(sudo grep -h '^THEMIS_DATABASE_DSN=' /etc/themis/evidence.env | cut -d= -f2- | sed 's|/evidence?.*||')
export THEMIS_API_KEY=$(cat ~/.themis-keys/operator)
./scripts/vm-verify.sh
# expect: each migration at its expected version, every reader at 0 pending, "no issues found"
unset THEMIS_API_KEY
```

**Going back** if the new version misbehaves: check out the commit saved in step 2, rebuild and
restart. New migrations stay in the database. Themis migrations normally only add tables and
columns, so older code usually runs on them, but read the PR first if it changed a migration.

```bash
cd /opt/themis/src/themis
git checkout $(cat ~/.themis-last-good)
env GOCACHE=$HOME/.cache/go-build GOMODCACHE=$HOME/go/pkg/mod go build -o bin/ ./cmd/... && sudo systemctl restart 'themis@*'
# later, to return to main: git checkout main
```

---

## Part A — Phase-3 greenfield services

The pipeline is **Evidence → Knowledge → Governance → Communication**, over a **Registry/Kernel**
foundation, with a supporting **Intelligence Gateway** beside it. Each is its own binary and **its own
database**, and since **M5** they collaborate over a real **event bus** (a dedicated `bus` PostgreSQL
database holding one `event_log`) plus read-only HTTP APIs — no shared business tables.

| Service | Command | Port | Own database | Reads over HTTP | Migrate on startup |
| ------- | ------- | ---- | ------------ | --------------- | ------------------ |
| Registry | `cmd/registry` | `:8082` | `evidence` (shared) | — | `THEMIS_REGISTRY_MIGRATE=1` (own bookkeeping table) |
| Evidence | `cmd/evidence` | `:8081` | `evidence` | Registry (in-proc) | `THEMIS_EVIDENCE_MIGRATE=1` |
| Knowledge | `cmd/knowledge` | `:8085` | `knowledge` | Evidence `:8081`, OSV | `THEMIS_KNOWLEDGE_MIGRATE=1` |
| Governance | `cmd/governance` | `:8083` | `governance` | Intelligence `:8086` (if AI on) | `THEMIS_GOVERNANCE_MIGRATE=1` |
| Communication | `cmd/communication` | `:8084` | `communication` | Governance `:8083` | `THEMIS_COMMUNICATION_MIGRATE=1` |
| Intelligence | `cmd/intelligence` | `:8086` | `intelligence` (optional, Δ3a) | Governance `:8083`, Knowledge `:8085`, bus (population) | `THEMIS_INTELLIGENCE_MIGRATE=1` (only if semantic precedent on) |
| **bus** | — | — | `bus` | — | `THEMIS_BUS_MIGRATE=1` (any pipeline svc) |

> **The event bus is the end-to-end switch.** Each of the four pipeline services relays its outbox to the
> bus and drains its upstream stream on a 2-second loop **only when `THEMIS_BUS_DATABASE_DSN` is set**. Leave
> it unset and the service falls back to a logging stand-in publisher with its reader disabled — a single
> context runs, but **an uploaded SBOM never crosses into Knowledge / Governance / Communication**. For an
> end-to-end SBOM→VEX flow, every pipeline service must point `THEMIS_BUS_DATABASE_DSN` at the same `bus`
> database.

> **Knowledge listens on `:8085`**, which is now its code default and matches the Governance node's
> `THEMIS_KNOWLEDGE_URL` default. (It used to default to `:8082` and collide with Registry; fixed
> 2026-08-07. Deployments that set `THEMIS_KNOWLEDGE_ADDR=:8085` explicitly are unaffected.)

> **Databases (5 required + 1 optional on one PostgreSQL server):** `evidence`, `knowledge`, `governance`,
> `communication`, `bus` — plus **`intelligence`** when Δ3a semantic precedent is enabled (the Operational
> Semantic Index; skip it to run the Gateway stateless).
> Registry co-locates in the **`evidence`** database — Evidence validates a release id in-process via
> `registry.ReleaseExists`, so the registry tables must live there. The database boundary keeps contexts
> structurally isolated.
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

Create the `themis` role and the databases (as the `postgres` superuser): the four pipeline databases
(`evidence` — which also co-locates the Registry identity schema — `knowledge`, `governance`,
`communication`), the shared `bus` event log, `auth` (the API-key store for inbound edge auth, F1), and
`intelligence` (the Δ3a Operational Semantic Index — harmless to create even if you run the Gateway
stateless).

> **Backup note (Δ4a):** most of the `intelligence` DB is disposable — the vector index rebuilds from
> Governance's Positions, and the invocation log is age-capped. But the Δ4a **golden set**
> (`golden_entries`) and **eval reports** (`eval_reports`) are the node's first NON-disposable state:
> a curated regression suite and its scoring history that a `TRUNCATE` would lose. If you rely on the
> eval harness, back this database up. Nothing in it is enterprise truth — it is operational state.

Set
the password **once** in a shell variable and reuse it everywhere — the runbook's DSNs read the same `$PGPW`,
so there is no second place to keep in sync:

```sh
# GENERATE the password — do not paste a literal one from a document. A named example in a runbook
# becomes a real production credential the first time someone follows the runbook, and it is then in
# every copy of that document. Letters/digits only: @ : / # ' $ would break the connection URL.
export PGPW=$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 24)
# Record it in your secret store NOW — it is printed nowhere else. Keep it exported for later steps.

sudo -u postgres psql -c "CREATE USER themis WITH PASSWORD '$PGPW';"
for db in evidence knowledge governance communication bus auth intelligence; do
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
> for db in evidence knowledge governance communication bus auth intelligence; do
>   sudo -u postgres psql -c "DROP DATABASE IF EXISTS $db WITH (FORCE);" -c "CREATE DATABASE $db OWNER themis;"
> done
> ```
>
> `WITH (FORCE)` (PostgreSQL 13+) terminates any lingering connection so the drop cannot hang.

### 2. Build the services

```sh
go build ./...     # compile-check everything (silent output = success)
# then produce the service binaries the runbook runs (cleaner than `go run` for six background processes):
go build -o bin/ ./cmd/registry ./cmd/evidence ./cmd/knowledge ./cmd/governance ./cmd/communication ./cmd/intelligence ./cmd/dashboard
ls bin/            # registry evidence knowledge governance communication intelligence dashboard
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
export THEMIS_OTLP_ENDPOINT=          # empty = console-only; e.g. otel-collector:4318 exports logs AND traces
                                      # (THEMIS_OTLP_LOGS_ENDPOINT is still read as a fallback)
                                      # Metrics are NOT pushed here — they are scraped from each node's /metrics
# Per-service, THEMIS_DATABASE_DSN points at that service's OWN database; the four pipeline services
# additionally point THEMIS_BUS_DATABASE_DSN at the shared `bus` database (this is what wires end-to-end).
export PGBASE="postgres://themis:$PGPW@localhost:5432"   # $PGPW from step 1 — re-export it in a new shell
export THEMIS_BUS_DATABASE_DSN="$PGBASE/bus?sslmode=disable"
```

### 4. Run the pipeline (start in this order)

Each service serves under `/api/v1` and runs its relay + reader loops in the background; the ones with
`*_MIGRATE=1` apply their own migrations on startup, and `THEMIS_BUS_MIGRATE=1` on Evidence creates the
shared `bus` event_log. Logs go to `logs/`.

**Registry self-migrates (since 2026-08-07).** Registry co-locates its identity tables in the `evidence`
database because Evidence reads them in-process. Both binaries therefore migrate the same database, and
golang-migrate's single default `schema_migrations` table used to make whichever ran second read the other's
version and silently skip its own `CREATE TABLE`s. Registry now keeps its **own**
`registry_schema_migrations` table, so `THEMIS_REGISTRY_MIGRATE=1` is safe.

Give it the **plain** DSN. The migrations-table parameter is attached internally to a separate migration
DSN and never reaches the connection pool — putting `x-migrations-table` on the shared DSN yourself still
breaks the running service, because pgx forwards the unknown parameter to Postgres and every connection is
rejected with `FATAL: unrecognized configuration parameter`.

Loading the SQL by hand also still works, and is the right choice if the DB role running the service should
not hold DDL rights. Load **all three** — `000001` is the Product→Project→Release identity, `000002` is the
enterprise **estate** graph (Customer / Microservice / Deployment) that the release blast-radius traversal
needs (C1/C2), and `000003` is the three **unique indexes** the idempotent creates require. Skip `000002`
and `GET /releases/{id}/blast-radius` returns an empty estate with the priority multiplier stuck at 1.0×;
skip `000003` and **every** `POST /products`, `/projects` and `/releases` answers `400`
`no unique or exclusion constraint matching the ON CONFLICT specification`, because find-or-create is
`INSERT … ON CONFLICT` against those indexes (EDR-INTAKE-01 B4):

```sh
psql "$PGBASE/evidence?sslmode=disable" -f internal/registry/adapters/store/migrations/000001_registry.up.sql
psql "$PGBASE/evidence?sslmode=disable" -f internal/registry/adapters/store/migrations/000002_estate.up.sql
psql "$PGBASE/evidence?sslmode=disable" -f internal/registry/adapters/store/migrations/000003_registry_uniqueness.up.sql
```

`000001` and `000002` are idempotent (`CREATE TABLE IF NOT EXISTS`); **`000003` is not** — it is one
transaction that refuses on existing duplicates and then creates the three indexes by name, so a second run
fails with `relation "registry_products_name_key" already exists` and changes nothing. If its pre-flight
refuses, the groups it names are yours to resolve: see section 8, "If migration 000003 refuses".

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
# :8085 is the code default since 2026-08-07 (it used to default to :8082 and collide with Registry);
# it stays spelled out here so the runbook reads the same as the systemd units and vm-verify.sh.
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
`X-API-Key` on every node's `/api/v1`, point each node at the shared `auth` database and mint a key.
Enforcement is **per node and at the inbound edge** — but the **credential is every caller's business,
including the other Themis nodes**, which is step 4a-bis below. Enabling the edge without giving the nodes
their keys breaks the pipeline silently; do the two together.

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
> pipeline turns auth **on for every service**, and `gf-upload-sbom.sh` run without `THEMIS_API_KEY` sends no
> key → every registration returns **401**. For an open end-to-end run, keep auth in its own shell (or
> `unset THEMIS_AUTH_DATABASE_DSN` before step 5); to run the pipeline WITH auth on, do 4a-bis below.

### 4a-bis. Switching auth on for every node

Section 4a switches on an **edge**. A Themis node is also a **caller**: Knowledge reads Evidence, Governance
reads Registry/Knowledge/Evidence (and calls Intelligence when AI is on), Communication reads
Governance/Registry, Intelligence reads Governance/Registry. Every one of those calls carries
**`THEMIS_API_KEY`** as `X-API-Key` when that node has one, and **no header at all** when it does not.

**Do both halves, or do neither.** With the edge on and the keys missing, the nodes keep running and
reporting healthy while the pipeline stops: Knowledge's inventory read answers 401, so an uploaded SBOM
correlates to nothing, no Finding opens, and the estate silently stops seeing vulnerabilities. That is why
this estate was found with Evidence, Registry and Governance on `AUTH DISABLED` (2026-10-13) — turning them
on had broken reads that sent no key.

**Which key each node needs.** One key per node, with the smallest scope its own calls need:

| Node | Calls | Scope |
| --- | --- | --- |
| `knowledge` | Evidence — inventory, document, identity candidates | `read` |
| `governance` | Registry, Knowledge, Evidence (reads) | `read` |
| `governance` | **+ Intelligence**, when `THEMIS_GOVERNANCE_AI_ENABLED=1` | **`admin`** — see below |
| `communication` | Governance, Registry (reads) | `read` |
| `intelligence` | Governance, Registry (reads) | `read` |
| `intelligence` | **+ the autonomous proposal push**, when the Δ4b pool is set | **`admin`** |
| `dashboard` | all six nodes (server-side injection, EDR-GUI-01 D4) | `admin` |
| `evidence`, `registry` | nothing — they call no other node over HTTP | — |

A **capability invoke is a POST**, so Intelligence's method-based write floor refuses a read-only key with
403 even though nothing there is mutated (EDR-SECURITY-01 D4 realization). Give the Governance node an
`admin` key whenever AI is enabled against an authenticated Intelligence; its error message says this when
it happens, rather than letting a 403 read as "the AI is disabled".

**Mint them** (from the repo root; each token prints **once**, only its bcrypt hash is stored):

```sh
export THEMIS_AUTH_DATABASE_DSN="$PGBASE/auth?sslmode=disable"
export THEMIS_AUTH_MIGRATE=1          # first run only: creates api_keys
# Use the built binary (go build -o bin/ ./cmd/authadmin) or `go run ./cmd/authadmin`.
./bin/authadmin create-key --name knowledge-read     --scopes read
./bin/authadmin create-key --name governance         --scopes admin   # read seams + the AI invoke
./bin/authadmin create-key --name communication-read --scopes read
./bin/authadmin create-key --name intelligence-read  --scopes read    # admin if the Δ4b sweep is on
./bin/authadmin create-key --name operator           --scopes admin   # for curl / the upload scripts
```

**Give each node its own env file**, so no node holds a credential it has no use for:

```sh
# per node: its inbound edge ...
THEMIS_AUTH_DATABASE_DSN=postgres://themis:...@localhost:5432/auth?sslmode=disable
THEMIS_AUTH_REQUIRED=1                # production guard: refuse to boot with an empty DSN
# ... and its own outbound credential (omit on evidence and registry — they call nobody)
THEMIS_API_KEY=<that node's token>
```

`deploy/systemd/install-systemd.sh` writes exactly these files and carries a commented
`THEMIS_API_KEY=<mint with: …>` slot in every node that needs one; `deploy/node.env.example` documents the
scope per node.

**Verify.** Each node's startup log says both halves — `API-key auth enabled (X-API-Key)` for the edge, and
a boolean `api_key_set` for its outbound calls (the key itself is never logged):

```sh
journalctl -u themis@knowledge -n 50 | grep -E "auth|api_key_set"
# then drive a real SBOM end to end — the only check that proves the inter-service calls authenticate:
env THEMIS_API_KEY=<operator token> ./scripts/gf-upload-sbom.sh -f sbom.json -p acme -j api -v 1.0.0 -c
env THEMIS_API_KEY=<operator token> ./scripts/release-posture.sh <release-id>   # a Finding appeared ⇒ Knowledge→Evidence authenticated
```

A 401/403 between nodes is never silent any more: the error names `THEMIS_API_KEY` and distinguishes *no key
sent* from *a key the peer refused*. The same scenario runs in CI as
`TestPipeline_SBOMToPublishedVEX_WithInboundAuthOnEveryNode` (`make e2e-pipeline`).

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
# Upload through the ONE intake door: the body IS the artifact, so --data-binary @FILE streams
# it however large, and `kind`/`format` are detected server-side and echoed on the receipt:
#   curl -s -X POST "localhost:8081/api/v1/intake?release_id=$RID" \
#     -H content-type:application/json --data-binary @./my-sbom.json | jq .
# (POST /api/v1/evidence is unchanged and still takes the JSON envelope
#  {kind,format,subject_release_id,document} — but it makes you JSON-escape the whole SBOM, and
#  an inline -d is capped at 128KB of argv on Linux, which is why intake takes the raw body.)

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

> **Between builds:** discovery runs at upload time, and the **re-discovery sweep** (default on,
> `THEMIS_REDISCOVERY_*`) re-runs it for the stalest releases so new CVEs reach a registered
> estate with nobody uploading anything. An **image-scan report** goes through the same intake
> door for second-opinion findings at scanner trust — raw Trivy JSON, Cortex JSON or Cortex CSV,
> sent as it came out of the tool and converted server-side (EDR-INTAKE-01 D4). The report needs
> its release's SBOM filed first (D6) or it is refused by name; TESTING.md § scanner reports has
> the full procedure.

> **The intake door, in one paragraph** (EDR-INTAKE-01). `POST /api/v1/intake` is the single
> door for SBOMs and vulnerability reports: the **body is the artifact** and the metadata is
> query parameters (`release_id`, or the `product`/`project`/`version` triple — resolved
> **read-only**, so intake never creates Registry identity). `kind` and `format` are detected
> from the body and echoed back. **CSV is a request encoding, never an evidence document** — a
> Cortex CSV is converted and the curated JSON is what gets filed. Every outcome is an
> addressable **receipt** (`GET /api/v1/intake/{id}`), including a refusal, which names itself
> from a closed taxonomy in two fields — `reason` and `detail`, never concatenated. With auth
> enabled (`THEMIS_AUTH_DATABASE_DSN`) send `X-API-Key`; the helper scripts send it from
> `THEMIS_API_KEY` when set. Tunables: `THEMIS_INTAKE_MAX_BYTES`,
> `THEMIS_INTAKE_INLINE_BUDGET`, `THEMIS_INTAKE_RECEIPT_TTL` (see `deploy/node.env.example`).

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
#    is path-safe (a hashed package token, no '/'), so it accepts directly:
PROP=$(curl -s "localhost:8083/api/v1/findings/$FID" | jq -r '.proposals[] | select(.stance=="not_affected") | .id' | head -1)
curl $J -X POST "localhost:8083/api/v1/findings/$FID/proposals/$PROP/accept" -d '{"actor_id":"you","actor_kind":"human"}'
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

### 5b. A CI pipeline uploads (the bot road — EDR-INTAKE-01 B1–B7)

Step 5 is the human road: register Product → Project → Release, then upload. A CI bot has nowhere to put the
"register the release first" step, and the version is the one part of the identity triple that is **new on
every build**. So intake accepts the `{product, project, version}` triple with **`create_release=true`** and
finds-or-creates **the version only**.

**A human creates the Product and the Project first.** Intake never creates identity above the version (B2):
those two names are enterprise identity, long-lived, and a typo in either must be a refusal rather than a
parallel estate. Create them once, by hand (step 5's `POST /api/v1/products` and `/api/v1/projects`, or the
dashboard's Admin tab) — after that the pipeline needs no Registry call at all.

**Two requests, SBOM first (B1).** One intake request files **one** artifact. A build that has both an SBOM and
a scanner report sends **two** requests, each retried independently, and the order matters: D6's
SBOM-before-report rule holds **across** them, so a report sent first is refused `no_inventory_for_release`.
The SBOM request is the one that carries `create_release=true` and creates the version; the report request
then finds it.

```sh
# 0. the triple a human already owns, plus whatever this build calls itself
export P=acme J_NAME=api V=R20.1.0
export BID="$CI_PIPELINE_ID"            # any label; see build_id below

# 1. the SBOM, FIRST — create_release=true, so intake creates the VERSION under acme/api
curl -s --fail-with-body -X POST \
  "http://localhost:8081/api/v1/intake?product=$P&project=$J_NAME&version=$V&create_release=true&build_id=$BID" \
  -H 'Content-Type: application/json' -H "X-API-Key: $THEMIS_API_KEY" \
  --data-binary @sbom.cdx.json | jq '{status, reason, detail, release_id, build_id, created}'

# 2. the scanner report, SECOND — the same triple, now WITHOUT create_release (the version exists).
#    Send the vendor file as it came out of the tool; Evidence converts it server-side.
curl -s --fail-with-body -X POST \
  "http://localhost:8081/api/v1/intake?product=$P&project=$J_NAME&version=$V&build_id=$BID" \
  -H 'Content-Type: application/json' -H "X-API-Key: $THEMIS_API_KEY" \
  --data-binary @trivy.json | jq '{status, reason, detail, release_id, findings_total, findings_skipped}'
```

Or let the helper script do request 1 — `-c` is `create_release=true` and `-b` is `build_id`:

```sh
# -c needs the whole triple explicitly (-p -j -v) and makes NO Registry call; -r and -c are exclusive
./scripts/gf-upload-sbom.sh -f sbom.cdx.json -p acme -j api -v R20.1.0 -c -b "$CI_PIPELINE_ID"
# it prints RELEASE_ID=<the id intake created-or-found>, read off the receipt
```

**`build_id` is provenance, and nothing reads it (B5).** At most **256 Unicode code points** and valid UTF-8;
over that it is refused by name (`400 build_id_invalid`) and **never truncated**. It is stored on the evidence
row and echoed on the receipt, and it takes no part in dedup, correlation or current-SBOM selection. One
consequence to expect rather than report as a bug: a byte-identical re-upload **dedups** and the filed document
keeps the **first** build's id, while the retry's own receipt carries its own — a receipt records an *attempt*,
the evidence row records what was *filed*.

**The key the pipeline should hold is `product:<id>`, not `admin`.** Mint one against the Registry id of the
product that pipeline builds (the `auth` database and its table come from §4a):

```sh
# the product id, by exact name (Registry read API)
export PID=$(curl -s "http://localhost:8082/api/v1/products?name=acme" | jq -r '.[0].id')

# mint the key — the token prints ONCE; only its bcrypt hash is stored. Either form works:
env THEMIS_AUTH_DATABASE_DSN="$PGBASE/auth?sslmode=disable" \
  go run ./cmd/authadmin create-key --name ci-acme --scopes "product:$PID" --ttl 2160h
# ...or the built binary, after: go build -o bin/ ./cmd/authadmin
# env THEMIS_AUTH_DATABASE_DSN="$PGBASE/auth?sslmode=disable" \
#   ./bin/authadmin create-key --name ci-acme --scopes "product:$PID" --ttl 2160h
# → key-<uuid>  <TOKEN>     # the pipeline holds the TOKEN as THEMIS_API_KEY
```

> **A `403` from intake means "this key is not for this product" — NOT "that product does not exist".**
> This is deliberate and it is the one thing to know before debugging one (B3). A `product:<P>` key naming any
> product other than its own gets the **same** `403 unauthorized` whether that product exists, does not exist,
> or is ambiguous — the three responses are identical **as bytes**. Otherwise intake would be a product-name
> oracle for the holder of any product key. The same holds on the `release_id` road: another product's release
> id and a release id that does not exist are one `403` (B7). So when a pipeline gets a `403`, check the key's
> scope against the product id *first*; the status code will never tell you the name was wrong. Only an
> **`admin`** key is told `404 unknown_release`, naming the part that missed, and only an `admin` key sees
> `422 ambiguous_name`. On an auth-disabled node there is no principal, so the caller is treated as `admin`.

TESTING.md § *bot intake* carries the full status-code table (every row of the contract) and the refusal
examples.

> **The same key may also create a *project* under its product, through Registry** (`POST :8082/api/v1/projects`
> — intake itself never creates a project). Registry confines a `product:<P>` key exactly as intake does:
> projects, releases and microservices only under product `P`, the same byte-identical `403` for a foreign or a
> missing product or project, and `POST /products` answers only with `P`'s own existing id (`200`, any case) —
> a product key never creates a product. Customers and deployments span products and need an `admin` key.
> A pipeline that knows only the product NAME looks the id up first:
>
> ```sh
> PID=$(curl -sf "http://localhost:8082/api/v1/products?name=acme" -H "X-API-Key: $THEMIS_API_KEY" | jq -r 'if length == 1 then .[0].id else empty end')
> curl -sf -X POST "http://localhost:8082/api/v1/projects" -H "X-API-Key: $THEMIS_API_KEY" -H "Content-Type: application/json" -d "{\"product_id\":\"$PID\",\"name\":\"acme-core\"}"
> ```

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
ollama pull nomic-embed-text   # embedding model for Δ3a semantic precedent (RC-1)

THEMIS_GOVERNANCE_URL=http://localhost:8083 \
THEMIS_OLLAMA_URL=http://localhost:11434 \
THEMIS_INTELLIGENCE_MODEL=cyberpal \
THEMIS_DATABASE_DSN="$PGBASE/intelligence?sslmode=disable" THEMIS_INTELLIGENCE_MIGRATE=1 \
THEMIS_INTELLIGENCE_EMBED_MODEL=nomic-embed-text \
THEMIS_BUS_DATABASE_DSN="$PGBASE/bus?sslmode=disable" \
THEMIS_INTELLIGENCE_ADDR=:8086 go run ./cmd/intelligence &   # grounds ONLY via the Governance projection, + Δ3a semantic precedent
```

The `THEMIS_DATABASE_DSN` + `THEMIS_BUS_DATABASE_DSN` lines enable **Δ3a semantic precedent** (RC-1): the
Gateway keeps its own `intelligence` index, its bus reader populates it from Governance Position events, and
`recommend_position` retrieves semantically similar **past** decisions to ground the model. **Omit both** to
run the Gateway stateless (exact-CVE precedent only) — everything else works identically. After changing
`THEMIS_INTELLIGENCE_EMBED_MODEL`, restart the node **once** with `THEMIS_INTELLIGENCE_REBUILD=1` to re-embed
the whole index under the new model.

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

### 6a. Dashboard (the GUI node — EDR-GUI-01)

`bin/dashboard` serves the Themis GUI at **`:8090`**: a static single-page app plus a same-origin
reverse proxy to the six read APIs — a **view**, never a context (no database, no truth; every
number on screen is fetched live). Run it beside the pipeline:

```sh
# open edge (dev / firewalled trial) — the node logs AUTH DISABLED:
./bin/dashboard &
# with node-side auth enabled (4a), give the proxy an ADMIN key (write-capable — the
# governed loop's accepts/publishes go through it; per-operator write PERMISSION is
# enforced at the dashboard's own gate, so a read-scoped operator still cannot decide):
#   THEMIS_API_KEY=<key minted with: authadmin create-key --name dashboard --scopes admin>
# to require sign-in (a dashboard username + password, or an operator's OWN key pasted
# once; a server-side session takes over, and the scope decides what the GUI allows):
#   THEMIS_AUTH_DATABASE_DSN="postgres://themis:$PGPW@localhost:5432/auth?sslmode=disable"
#   THEMIS_DASHBOARD_MIGRATE=1   # create the dashboard's own login table + seed admin
# production guard (refuses to boot with an open edge):
#   THEMIS_AUTH_REQUIRED=1
```

**The default login is `admin` / `Themis@123` — change it first.** With
`THEMIS_AUTH_DATABASE_DSN` set, the dashboard creates its own `dashboard_users` table in the
`auth` database (`THEMIS_DASHBOARD_MIGRATE=1`, under its own `dashboard_schema_migrations`
bookkeeping table) and seeds that one account. Sign in, open the **Admin** tab, and set a
password of your own: current → new → confirm. There are no complexity requirements. Until you
do, the Admin tab and the topbar both say the default password is still in use, and changing it
signs out every other browser signed in as `admin`. An existing row is never overwritten, so a
restart or a re-install cannot put the default back.

`THEMIS_DASHBOARD_MIGRATE=1` reads its SQL from a path that defaults to the **relative**
`internal/dashboard/migrations`, resolved against the node's working directory — fine when you
run `./bin/dashboard` from the repo root, and fine under the systemd unit, whose
`WorkingDirectory=` is the repo. Anywhere else (a binary copied to `/usr/local/bin`, a
container with a different workdir), set `THEMIS_DASHBOARD_MIGRATIONS` to an **absolute** path.
If the directory does not resolve, the node refuses to start and names both the path it looked
for and that variable.

Two things worth knowing about that account. It is **shared**: every decision taken through it
is stamped `admin` in the append-only audit trail, so an operator who needs their own name on a
record signs in with their own API key instead (the paste form is still on the login page,
below the password form). And it is **the dashboard's own** credential — it is not an
`internal/platform/auth` API key, so `authadmin revoke-key` has nothing to do with it; the
Admin tab is where it changes.

Beyond a firewalled network, **front `:8090` with a TLS-terminating reverse proxy** (send
`X-Forwarded-Proto: https` so the session cookie turns `Secure`) — sign-in is the one moment a
password or a long-lived key transits the wire. All options are documented in
[`deploy/node.env.example`](deploy/node.env.example).

### 7. Run as systemd services (survive logout / reboot)

Steps 4–6 run the services as background jobs of your shell — fine for a trial, but they die when the shell
exits. To install them as managed **systemd** services (auto-start on boot, restart on failure, logs in
journald), use the installer under [`deploy/systemd/`](deploy/systemd). Build the binaries (step 2), make
sure the databases exist (step 1), then stop any hand-started copies so they don't hold the ports:

```sh
# from the repo root, as root, with the DB password (and your Ollama model tag):
pkill -f 'bin/(registry|evidence|knowledge|governance|communication|intelligence|dashboard)' || true
sudo THEMIS_PGPW="$PGPW" THEMIS_INTELLIGENCE_MODEL='<ollama-model:tag>' \
  ./deploy/systemd/install-systemd.sh
```

> **`THEMIS_PGPW` must be the password the `themis` role actually has** — pass `$PGPW` from step 1 rather
> than retyping one. The installer bakes it into six `EnvironmentFile`s, and **changing the role's password
> afterwards does not update them.** That failure is nastier than it sounds: `pgx` pools keep serving on
> connections opened before the change, so every node looks healthy for hours or days and they all fail
> together at the next restart — governance loudest, because it refuses to start at all when it cannot
> authenticate to run its migrations. If you ever rotate the password, rewrite the env files in the same
> maintenance window:
>
> ```sh
> sudo NEWPW="$NEWPW" bash -c 'for f in /etc/themis/*.env; do sed -i "s|://themis:[^@]*@|://themis:${NEWPW}@|g" "$f"; done'
> sudo systemctl restart 'themis@*'
> ```

It writes one `EnvironmentFile` per service under `/etc/themis/` (mode 0600, root-only: they hold
the database password), installs a single templated `themis@.service`, and enables + starts all seven
`themis@{registry,evidence,knowledge,governance,communication,intelligence,dashboard}`. Registry
migrates itself on start (`THEMIS_REGISTRY_MIGRATE=1`). The env files it writes are auth-OFF; R1
steps 5–6 switch auth on. Manage them the usual way:

```sh
systemctl status 'themis@*'                 # all seven
sudo systemctl restart themis@knowledge     # e.g. after a rebuild
journalctl -u themis@knowledge -f           # follow logs
```

To change configuration, edit `/etc/themis/<service>.env` then `sudo systemctl restart themis@<service>`.
`WorkingDirectory` is the repo root (services resolve their migrations by a relative path), so keep the
built `bin/` in place.

### 7a. Network edge: loopback nodes, TLS in front of the dashboard, a host firewall (VM-NET-1)

Measured 2026-10-13: the VM served every node on every interface (`ss -ltnp` showed `*:8081`
… `*:8090`) with no host firewall, so the GUI login and every API key crossed the office network
in clear text. Since every node requires `X-API-Key`, that is not an open write surface — but a
pasted key is a key, and a password is a password. Three steps close it; each is reversible.

1. **Bind every node to loopback.** All seven run on one host and reach each other by
   `localhost`, so nothing needs a routable listener. In each `/etc/themis/<svc>.env` set the
   listen address to `127.0.0.1:<port>` (`THEMIS_EVIDENCE_ADDR=127.0.0.1:8081`,
   `THEMIS_REGISTRY_ADDR=127.0.0.1:8082`, `THEMIS_GOVERNANCE_ADDR=127.0.0.1:8083`,
   `THEMIS_COMMUNICATION_ADDR=127.0.0.1:8084`, `THEMIS_KNOWLEDGE_ADDR=127.0.0.1:8085`,
   `THEMIS_INTELLIGENCE_ADDR=127.0.0.1:8086`, `THEMIS_DASHBOARD_ADDR=127.0.0.1:8090`), then
   `sudo systemctl restart 'themis@*'`. The `*_URL` variables already say `localhost`.
2. **Put TLS in front of the dashboard.** [`deploy/edge/Caddyfile.example`](deploy/edge/Caddyfile.example)
   terminates HTTPS on 443 and proxies to `127.0.0.1:8090` (Rocky: `dnf install caddy` from EPEL;
   Ubuntu: Caddy's own apt repository, `apt-get install caddy`); Caddy adds `X-Forwarded-Proto`, so
   the session cookie turns `Secure` (EDR-GUI-01 D3). `tls internal` uses Caddy's local CA
   (browsers on the office network trust it after `caddy trust`, or install a real certificate
   and delete the line). Copy it to `/etc/caddy/Caddyfile` with the VM's own names — full name, short name and
   address, since Caddy answers TLS only for a name it has a certificate for — and
   `sudo systemctl enable --now caddy`. Three API routes ride the same 443 for a build system:
   `/evidence/` → the intake (a CI job uploads with its product-scoped key), `/registry/` → the
   Registry (the same job finds-or-creates its project and version with the same key, which the
   Registry confines to the key's own product), and `/communication/` → the CI callback
   (`delivery:callback` key); the prefix is stripped, so a job calls
   `https://<vm>/registry/api/v1/projects`, `https://<vm>/evidence/api/v1/intake?…` and
   `https://<vm>/communication/api/v1/callbacks/ci-rebuild`. The other nodes are NOT published:
   scripts run on the host, and a remote caller for one of them is the moment to add a block,
   deliberately. The CI host must trust the certificate: with `tls internal`, import Caddy's
   local root (`/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt`) there, or use
   a company certificate instead.
3. **Allow only SSH and HTTPS in.** [`deploy/edge/firewall.sh`](deploy/edge/firewall.sh) is a
   dry run by default and prints what it would do; `sudo ./deploy/edge/firewall.sh --apply`
   enables the host firewall — firewalld on Rocky/RHEL, ufw on Ubuntu/Debian, whichever the host
   has — with `ssh` and `https` only, and removes any earlier opening of 8081–8086, 8090 and 5432. Verify with `ss -ltnp` (every Themis port on `127.0.0.1`) and
   `firewall-cmd --list-all`.

`scripts/vm-verify.sh` is unaffected: it reads the nodes over `localhost`.

### 8. Upgrade an existing deployment (pull, build, restart)

The steps are [R3. Pull the latest code and restart](#r3-pull-the-latest-code-and-restart) at the top of
this file. An upgrade is not a re-install: the installer in step 7 writes `/etc/themis/<svc>.env`
only when it creates it, so settings added since your install are **not** picked up by re-running
it — R3 step 4 adds them.

**After an upgrade that changed how Themis reads a version** (KN-GO-1, 2026-10-14: `go1.27.1` now
compares as 1.27.1), the Findings already open are not re-judged on their own — the rule runs on an
enrichment, and the cards did not change. Run the one-time pass once (KN-GO-2):

```sh
# 1. set the switch, restart governance, read the result line, unset the switch
echo 'THEMIS_GOVERNANCE_REJUDGE_RANGES=1' | sudo tee -a /etc/themis/governance.env
sudo systemctl restart themis@governance
sleep 30
sudo journalctl -u themis@governance --since '-2 min' --no-pager | grep 're-judge'
# expect: "version-range re-judge done" with faultlines / raised / vendor_raised / skipped counts
sudo sed -i '/^THEMIS_GOVERNANCE_REJUDGE_RANGES=/d' /etc/themis/governance.env
```

It applies the same version-range rule an enrichment applies, so only Findings whose every
component is provably outside the card's range get a system `not_affected` proposal, and the
configured policy decides as usual. Since VEX-RAISE-1 the same pass also re-applies the vendor
overlay: a Finding born after the vendor's `not_affected` statement arrived gets the proposal it
never got (`vendor_raised`). Vendor evidence waits for a person; sign the applicable ones in one
run with `scripts/vex-accept-applicable.sh` (dry run first, then `--apply` with `THEMIS_ACTOR_ID`).
With `THEMIS_REGISTRY_URL` set the pass also runs same-CVE roll-forward (EDR-ROLLFORWARD-01): a
Finding whose CVE a sibling release of the same project already judged gets that decision as a
proposal for a person to accept (`rollforward_raised`). Leaving the switch set is harmless (the pass is idempotent)
but wasteful, which is why the last line removes it.

**If the cards themselves carry the old split ranges** (KN-GO-3: a Go card reading
`["<1.4.3", ">=0"]`, written by the OSV reader before 2026-10-14), run Knowledge's one-time
range repair FIRST, then the Governance pass above — the repair folds corrected statements, and
the enrichment fan-out usually clears the Findings before the pass is even needed:

```sh
echo 'THEMIS_KNOWLEDGE_REPAIR_RANGES=1' | sudo tee -a /etc/themis/knowledge.env
sudo systemctl restart themis@knowledge
sleep 60
sudo journalctl -u themis@knowledge --since '-3 min' --no-pager | grep 'range repair'
# expect: "range repair done" with cards / repaired counts
sudo sed -i '/^THEMIS_KNOWLEDGE_REPAIR_RANGES=/d' /etc/themis/knowledge.env
```

Proposals the rule raised BEFORE the range grading was corrected (KN-GO-4) stay `proposed` with
`asserted` evidence and are never re-graded. Review and accept them as a person:

```sh
# dry run first — lists every standing version-range proposal; then --apply under your name
PGBASE=... ./scripts/range-accept-provable.sh
PGBASE=... THEMIS_ACTOR_ID=<you> THEMIS_API_KEY=$(cat ~/.themis-keys/operator) ./scripts/range-accept-provable.sh --apply
```

Things the 2026-10-12 upgrade ran into:

- **A halted stream survives an upgrade and a reboot.** The reader resumes at its cursor, re-reads
  the poison event and halts again. Mark the envelope applied in the consumer's
  `processed_events` first (the 2026-10-09 checkpoint in `docs/engineering/PHASE3-STATUS.md` has
  the exact commands), then restart.
- **A large SBOM takes minutes to correlate.** 555 components took about 4.5 minutes. During that
  time Knowledge's `stream_cursor` does not move, because it advances only after the event is
  handled. A gap between the cursor and `max(seq)` is not a backlog by itself: `seq` is shared by
  every stream, so compare against `max(seq)` for the one `source_context`.
- **Keep your API key somewhere that survives a reboot.** Keys are stored as bcrypt hashes and
  cannot be read back; a lost key means minting a new one with `bin/authadmin create-key` (4a).
  A file only you can read works: `( umask 077; … > ~/.themis.key )`, then
  `export THEMIS_API_KEY=$(cat ~/.themis.key)`.
- **Reaching the GUI from your laptop** when the VM is firewalled: an SSH tunnel,
  `ssh -N -L 8090:localhost:8090 <user>@<vm-host>`, then open `http://localhost:8090`.

#### If migration 000003 refuses (Registry uniqueness)

Registry's `000003_registry_uniqueness` adds the three unique indexes — products on
`lower(name)`, projects on `(product_id, lower(name))`, releases on `(project_id, version)` — behind
a pre-flight that **refuses rather than repairs** (EDR-INTAKE-01 B4): merging two products means
re-pointing projects, releases, evidence, findings and positions, which is an estate decision and
not something a migration may take while you watch a progress line. The 2026-10-12 census found no
duplicates, including case-insensitive ones, so this is expected not to fire.

**Which database.** Registry has no database of its own: its identity tables are **co-located in
the `evidence` database** (the topology table in Part A, and the `createdb` loop in step 1, which
creates no `registry` DB), and it keeps its own `registry_schema_migrations` bookkeeping table
there so it never reads Evidence's version. So every command below targets `evidence` and the
**table** — not the database — is what carries the word "registry". `scripts/vm-verify.sh` reads
the same pair.

**Symptom.** Registry exits at startup logging `migrate failed` with
`registry uniqueness pre-flight refused: duplicate rows exist …`, followed by one line per
offending group naming the value, the row count and the ids.
golang-migrate marks the version row **before** running the file, so `registry_schema_migrations`
is left at `version=3, dirty=true` and a plain restart will **not** retry it.

```sh
# 1. Read the groups the refusal named, then resolve them yourself — the migration will not.
#    These are the same three queries, read-only, if you want the list again. The registry
#    tables live in the `evidence` database (see "Which database" above).
psql "$PGBASE/evidence?sslmode=disable" -c "SELECT lower(name), count(*), array_agg(id) FROM products GROUP BY lower(name) HAVING count(*) > 1"
psql "$PGBASE/evidence?sslmode=disable" -c "SELECT product_id, lower(name), count(*), array_agg(id) FROM projects GROUP BY product_id, lower(name) HAVING count(*) > 1"
psql "$PGBASE/evidence?sslmode=disable" -c "SELECT project_id, version, count(*), array_agg(id) FROM releases GROUP BY project_id, version HAVING count(*) > 1"
# 2. Clear the dirty flag by forcing the version back to 2 — the refused migration changed
#    nothing, so there is nothing to undo. x-migrations-table is what points golang-migrate at
#    Registry's own row instead of Evidence's; without it you would force the WRONG version.
migrate -path internal/registry/adapters/store/migrations \
        -database "$PGBASE/evidence?sslmode=disable&x-migrations-table=registry_schema_migrations" \
        force 2
# 3. Re-run. Registry applies 000003 again on startup.
sudo systemctl restart themis@registry
PGBASE=... ./scripts/vm-verify.sh            # registry at the expected migration version
```

Without the `migrate` CLI, step 2 is
`UPDATE registry_schema_migrations SET version = 2, dirty = false;` on the `evidence` database
(Registry's table, Evidence's database — see above) — and nothing else, because the refusal
rolled its own transaction back.

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
