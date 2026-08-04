# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

Themis is an open-source Go security-intelligence platform: it ingests SBOM/VEX documents, correlates
vulnerabilities against live CVE feeds, applies VEX overlay semantics, governs enterprise positions, and
publishes standards-based artifacts. Backed by PostgreSQL. No UI, no external broker, single static binaries.

**The repository holds two code trees at once — know which one you are in before editing:**

| Tree | Path shape | Status |
| --- | --- | --- |
| **Legacy PoC (v0.3.x monolith)** | `internal/{domain,usecase,adapter,infrastructure}`, `cmd/themis` | **Frozen. Reference only. Do not modify.** |
| **Phase-3 greenfield rebuild** | `internal/<context>/{domain,app,adapters}`, `cmd/<context>` | **The sole go-forward. All new work lands here.** |

The greenfield rebuild splits the monolith into independently-deployable bounded-context services. Start any
session at [`docs/engineering/PHASE3-STATUS.md`](docs/engineering/PHASE3-STATUS.md) and
[`docs/BACKLOG.md`](docs/BACKLOG.md).

## Standing ground rules (override defaults)

- **The legacy `internal/{domain,usecase,adapter,infrastructure}` tree is frozen at v0.3.x and is
  reference-only.** Never modify it. The one sanctioned exception on record is the NVD CVSS-4.0 maintenance
  fix in `internal/adapter/nvd`; do not extend the exception without explicit user direction.
- **ADR wins.** Where an ADR (`docs/adr/`) or an EDR (`docs/engineering/decisions/`) constrains a choice,
  that document is the reason of record — over the PoC, over intuition. `STACK.md` + `CONVENTIONS.md` are
  the standing cross-cutting rules; read them before implementing.
- **OpenSpec is the system of record** for greenfield work (`openspec/changes/phase3-*`). `phase3-*` changes
  use proposal/design/tasks + an EDR as source of truth and carry **no `specs/` deltas**, so
  `openspec validate` reporting "no deltas" is expected, and you archive with
  `openspec archive <name> --skip-specs -y`.
- **Commit and push only when the user explicitly asks.** Do not commit, push, or open PRs on your own
  initiative, even after a green `make check`.
- **The `.cursor/rules/*.mdc` files are `alwaysApply: true` but describe the frozen v0.3.x PoC** (the
  `usecase/adapter/infrastructure` layers, the three-layer data model, "treat as current intent"). For
  greenfield work they are superseded by this file, the ADRs/EDRs, `STACK.md`, and `CONVENTIONS.md` — do not
  read them as go-forward intent.

## Commands

```sh
go build ./...          # build every service (greenfield + monolith)
make check              # THE quality gate (whole repo) — must pass before any commit
make check-ci           # what CI runs: same gate, coverage greenfield-only (frozen legacy excluded)
make build              # build the v0.3.x monolith to ./bin/themis

make test               # unit tests (no build tags)
make test-integration   # integration tests: -tags=integration -p 1 (real embedded Postgres)
make test-property      # property tests (rapid), -rapid.checks=1000 by default
make lint               # golangci-lint v2
make clean-arch         # go-cleanarch: monolith + each greenfield context (see below)
make arch-test          # ./tests/architecture — the Go architecture test
make coverage           # scripts/check-coverage.sh, per-package tiers
make deadcode           # x/tools deadcode (non-fatal reporter, exits 0)

make e2e-evidence       # Evidence context end-to-end (register → upload SBOM → inventory)
make e2e-pipeline       # M5 multi-context pipeline over the event bus (-tags=e2e ./tests/pipeline/...)
make e2e-llm            # Intelligence real-model e2e against a live OpenAI-compatible server
```

`make check` runs: **build · test · lint · clean-arch · arch-test · coverage · deadcode** — and coverage pulls in
the integration tests. Every OpenSpec `tasks.md` group ends by making this green. `make check-ci` is the
same gate but swaps `coverage` for `coverage-greenfield` (go-forward tree only); it — not `make check` — is
what `.github/workflows/{pr,main}.yml` enforce, because the frozen v0.3.x legacy integration tests are green
only on macOS's coarse clock.

`make e2e-llm` is **opt-in** (`//go:build llm`, excluded from `make check`): it drives `recommend_position`
against a real OpenAI-compatible endpoint and needs `THEMIS_LLM_URL` / `THEMIS_LLM_MODEL` (plus
`THEMIS_LLM_API_KEY` and `THEMIS_LLM_RESPONSE_FORMAT=json_schema` for servers like LM Studio that require a
bearer token and reject `json_object`); it skips if the endpoint is unreachable. See `TESTING.md`.
`THEMIS_LLM_TIMEOUT` (Go duration, default `60s`) is the provider HTTP-client timeout — **raise it for a
slower/larger local model** whose grounded `recommend_position` exceeds 60s, else the call aborts with
`provider_error` and the Gateway returns an `insufficient` (204), which reads like a bad recommendation but is
really a timeout.

**Run a single test** (add `-tags=integration` for integration/embedded-Postgres tests):

```sh
go test -run TestFaultlineReuseAcrossSBOMs ./internal/knowledge/adapters/store/
go test -tags=integration -run TestFaultlineLifecycleDemo -v ./internal/knowledge/adapters/store/
```

**Regenerate an API** after editing its OpenAPI spec (spec-first — handlers are generated, never
hand-edited): `make generate-api-<context>` (e.g. `generate-api-knowledge`). Specs live in
`api/<context>.openapi.yaml`; the monolith's is `api/openapi.yaml`.

## Running the greenfield stack

The end-to-end operator runbook is [`INSTALLATION.md`](INSTALLATION.md) Part A (install Postgres → create the
databases → `go build -o bin/ ./cmd/...` → export env → run each node → drive an SBOM).
`deploy/node.env.example` is the self-documented env template (CONVENTIONS.md R2);
`deploy/systemd/install-systemd.sh` generates `/etc/themis/<svc>.env` + a templated `themis@.service` unit for
all six nodes.

- **Topology: one Postgres server, six databases** — `evidence` (the `registry` schema **co-locates** here),
  `knowledge`, `governance`, `communication`, `bus`, and `auth` (the shared API-key store; see the auth switch
  below). Ports: Evidence `:8081`, Registry `:8082`,
  Governance `:8083`, Communication `:8084`, Intelligence `:8086`, and **Knowledge `:8085`** — its code default
  is `:8082`, which collides with Registry, so you **must** set `THEMIS_KNOWLEDGE_ADDR=:8085` (the port every
  other node's `THEMIS_KNOWLEDGE_URL` already defaults to).
- **`THEMIS_BUS_DATABASE_DSN` is the cross-context switch.** Set it on every node ⇒ the relay publishes and each
  reader drains the `bus` DB, so events actually cross contexts. Leave it unset ⇒ a log-only publisher and
  disabled readers (single-context dev; nothing propagates).
- **`THEMIS_AUTH_DATABASE_DSN` is the inbound-edge auth switch (F1, EDR-SECURITY-01).** Set it on a node ⇒ that
  node's `/api/v1` requires a valid `X-API-Key`; leave it unset ⇒ auth is disabled (dev) and the node logs
  `AUTH DISABLED` — **unless** `THEMIS_AUTH_REQUIRED=1`, which hard-fails startup when the DSN is empty (a
  production guard so a node can never boot open). Mint keys with `cmd/authadmin`:
  `THEMIS_AUTH_DATABASE_DSN=… THEMIS_AUTH_MIGRATE=1 go run ./cmd/authadmin create-key --name ci --scopes admin`
  (`--scopes` ∈ `admin`=read+write, `read`=read-only; prints the token **once**, stores only its bcrypt hash;
  `revoke-key --id` disables one). Auth is **inbound-edge only** — inter-service read clients send no key.
- **Registry does not self-migrate** into the shared `evidence` DB — load its schema with
  `psql -f internal/registry/adapters/store/migrations/000001_registry.up.sql` **and**
  `…/000002_estate.up.sql` (the enterprise estate graph, C1) and run it with a **plain** DSN
  (an `x-migrations-table` DSN param breaks the pgx pool at runtime).
- **Drive an SBOM:** `scripts/gf-upload-sbom.sh` registers Product→Project→Release and uploads (auto-detects
  CycloneDX/SPDX; streams large files via `curl --data-binary @-`; `-r` reuses a release). Evidence is
  content-addressed, so re-uploading byte-identical content **dedups** — a re-run needs changed bytes.
- **Opt-in enrichment** (off by default — no silent outbound calls; all **relevance-bounded** per
  EDR-KNOWLEDGE-01 D5, i.e. feeds enrich *existing* Faultlines and never mirror the full feed):
  `THEMIS_NVD_ENABLED=1` (authoritative CVSS/severity via the modified-since watch),
  `THEMIS_EPSSKEV_ENABLED=1` (EPSS/KEV/ExploitDB signal sweep),
  `THEMIS_REDHAT_ENABLED=1` (per-CVE Red Hat vendor severity + `not_affected` applicability + RPM fixed-version
  bounds; covers RHEL/Rocky/Alma — EDR-VEX-01 Phase 3), and
  `THEMIS_VEXFEED_ENABLED=1` + `THEMIS_VEXFEED_URLS=<csaf-base,…>` (generic per-CVE CSAF-VEX directories at
  `<base>/<year>/cve-<id>.json` — EDR-VEX-01 B4). Each feed also honors `_URL`/`_POLL_INTERVAL` (default 12h).
  OSV distro + language correlation is always on.

## Architecture

### Clean Architecture, context-first (greenfield)

Each bounded context is `internal/<context>/{domain,app,adapters}` with **inward-only imports**
(`domain` ← `app` ← `adapters`; the `cmd/<context>` composition root wires everything):

- `domain` — pure Go: aggregates, value objects, invariants. No I/O, no logging, no framework imports.
- `app` — use cases + ports (interfaces). Orchestrates the domain; depends only on `domain`.
- `adapters` — Postgres stores, HTTP handlers, feed/serializer ACLs, inbound event consumers. The only ring
  allowed to import drivers and the shared platform packages.

**No cross-context imports.** Contexts collaborate **only** via (a) domain **events** through a transactional
outbox + relay, and (b) read-only **HTTP read APIs** (a consuming context talks to a small client seam, e.g.
Knowledge's `adapters/evidence` client reads Evidence's inventory). This rule is enforced, not aspirational.

**Event transport (M5, `internal/platform/eventbus`).** The events above ride a platform-owned bus — one of
three shared platform packages (`observability`, `eventbus`, and the inbound-edge `auth`; only adapters + the
`cmd` composition root may import them). Topology is one PostgreSQL server, **database-per-context
plus a dedicated `bus` database** holding a single `event_log` (a Postgres stand-in for a Kafka topic): a
Publisher appends each outbox note to it, a stream Reader drains rows in `seq` order filtered by
`source_context`, and delivers a kernel `Envelope` to each context's inbound `Consumer.Handle`. The database
boundary makes context isolation structural (no cross-database joins). The bus is **business-agnostic** — it
moves kernel `Envelope`s and imports no bounded context — so a real broker can later slot behind the same
`Envelope` + ports. Source of record: `docs/engineering/decisions/EDR-EVENTBUS-01.md` (D1–D11).

The contexts and their pipeline order:

**Kernel/Registry** (shared value objects + Product→Project→Release identity, plus the enterprise **estate
graph** Product→Microservice→Deployment→Customer and a `GET /releases/{id}/blast-radius` traversal that counts
the unique customers a release reaches — C1) → **Evidence** (immutable,
content-addressed SBOM/VEX; canonical inventory) → **Knowledge** (Faultline aggregate; order-independent
reconciliation; feed ACLs; correlation) → **Governance** (Findings + append-only Enterprise Positions — AI
proposes, humans/policy decide; triage priority is `base_score × blast-multiplier`, the multiplier derived
from Registry's blast-radius over the read seam `THEMIS_REGISTRY_URL`, **fail-safe to 1.0** when Registry is
unreachable, and saturating to 2.0× at `THEMIS_BLAST_RADIUS_CAP` unique customers (default 10) — C2) →
**Communication** (deterministic Publication materialization + serializer
registry). Beside the pipeline sits **Intelligence** — a reactive AI Gateway; all provider/LLM code is
confined here behind a provider port (`internal/intelligence/adapters/`), it has no truth-store driver, and
it reads via read APIs / writes via proposal-intake.

### Enforcement details worth knowing

- **clean-arch runs per naming scheme.** `go-cleanarch`'s flat model can't mix the monolith's
  `usecase/adapter/infrastructure` names with the greenfield `app/adapters` names in one pass, so the
  `clean-arch` target invokes it once for `./internal` (monolith layout) and once per greenfield context with
  `-domain domain -application app -interfaces adapters`. **go-cleanarch scans test files too** — a
  cross-layer test placed in the wrong ring directory will fail the check.
- **depguard** blocks illegal imports (including the shared observability package leaking into `domain`/`app`
  — only adapters + the composition root may import it). The same guard (`platform-eventbus-infra-only`) plus
  the arch test `TestPlatformEventbusIsBusinessAgnostic` keep `internal/platform/eventbus` importable only by
  adapters + `cmd`, and keep it free of any bounded context or the registry — kernel + drivers only.
- **Coverage tiers** (`scripts/check-coverage.sh`; a package must be registered there): `domain`/`app` →
  **100%**, adapters/infra → **90%**, aggregate **stores** → **80%** (store DB-error branches need pool-fault
  injection, a tracked follow-up). Each greenfield store also owns a `migrations/` dir under its
  `adapters/store/` and up/down reversibility is a task gate.

### Cross-cutting conventions (`docs/engineering/CONVENTIONS.md`)

- **R1 — every node logs to console AND OpenTelemetry**, wired from one shared package
  (`internal/platform/observability`): a single `log.Info(...)` tees a console line and an OTel log record.
  The `domain`/`app` rings never log. No `fmt.Print*` as telemetry; redact secrets/PII before emitting;
  carry a correlation id.
- **R2 — configuration is self-documented** with inline comments in a shipped example config; secrets are
  referenced (env var / secret ref), never inlined.

### Stack (see `docs/engineering/STACK.md` for the justified list)

Go 1.25 · PostgreSQL via `pgx/v5` · `golang-migrate/v4` · `chi/v5` · `oapi-codegen/v2` (spec-first) ·
`santhosh-tekuri/jsonschema/v6` · OpenTelemetry + `zap` + `prometheus/client_golang` · std-lib `testing` +
`pgregory.net/rapid` (property) + `fergusstrange/embedded-postgres` (integration). No ORM, no heavy web
framework, **no external broker** — event delivery is a Postgres transactional outbox + relay draining into a
dedicated `bus` database (`internal/platform/eventbus`); a broker can slot behind the same event envelope later. Standards-only formats: CycloneDX/SPDX in; CycloneDX-VEX /
OpenVEX / CSAF out.

## Key invariants

- **Faultline** = one enterprise card per canonical CVE (own opaque id; the CVE is an alias, normalized from
  distro aliases). Source **Proposals** are append-only (audit); the reconciled view is deterministic by
  source precedence; lifecycle is forward-only (Created→Enriched→Correlated→Mature→Superseded) — a card is
  **never deleted**, only superseded. Duplicate CVE from a later SBOM **reuses** the existing card.
- **VEX overlays, never deletes** — VEX changes effective/enterprise state only; raw findings are preserved.
  Vendor VEX (Red Hat / CSAF feeds) is *gathered, not obeyed*: a reconciled `not_affected` statement raises a
  **system Proposal** on the Findings whose component it covers, which policy auto-accepts or a human decides —
  it never auto-suppresses (EDR-VEX-01; "Gathering Is Not Knowing").
- **AI is advisory** — the Intelligence Gateway *proposes* a position; humans or policy decide. It is
  disable-able and never auto-decides.

## Scripts & tooling

- `scripts/list-open-vulns.sh` — auto-discovers API key + product ids and lists open vulnerabilities via the
  API, with a day-over-day snapshot diff.
- `scripts/release-smoke-test.sh` — one-command release test (build → fresh DB → migrate → run → register →
  upload the SBOM under `scripts/` → verify components + enrichment). Wrapped by the `/themis-release-test`
  skill.
- `scripts/gf-upload-sbom.sh` — the **greenfield** register-and-upload driver (Product→Project→Release + SBOM);
  see "Running the greenfield stack" above. `deploy/systemd/` holds the systemd unit template + generator.
- Defects and go-forward gaps are tracked in [`docs/BACKLOG.md`](docs/BACKLOG.md) — **Part 1** is the active
  greenfield tracker (open this first); **Part 2** is the frozen legacy-PoC history (e.g. D-NVD-2, D-FEED-2).
- Monolith→greenfield capability parity (what has and hasn't carried over) is tracked in
  [`docs/engineering/PARITY-GAP.md`](docs/engineering/PARITY-GAP.md); resume any session at
  [`docs/engineering/PHASE3-STATUS.md`](docs/engineering/PHASE3-STATUS.md).

## Permission and related

### Allowed without asking

- Formatting
- Lint fixes
- Tests
- Bug fixes
- Small refactoring
- Documentation
- Comments

### Must ask

- New package
- New dependency
- New service
- New module
- New directory structure
- New architectural pattern
- API change
- Domain model change
- Build changes
- CI changes
- Security model changes

### Before asking

Provide:

1. Why the change is needed.
2. Alternatives considered.
3. Impact.
4. Files affected.

Wait for approval.