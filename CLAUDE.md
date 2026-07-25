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
[`PHASE3-BACKLOG.md`](docs/engineering/PHASE3-BACKLOG.md).

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

## Commands

```sh
go build ./...          # build every service (greenfield + monolith)
make check              # THE quality gate — must pass before any commit
make build              # build the v0.3.x monolith to ./bin/themis

make test               # unit tests (no build tags)
make test-integration   # integration tests: -tags=integration -p 1 (real embedded Postgres)
make test-property      # property tests (rapid), -rapid.checks=1000 by default
make lint               # golangci-lint v2
make clean-arch         # go-cleanarch: monolith + each greenfield context (see below)
make arch-test          # ./tests/architecture — the Go architecture test
make coverage           # scripts/check-coverage.sh, per-package tiers
make deadcode           # x/tools deadcode (non-fatal reporter, exits 0)
```

`make check` runs: **build · lint · clean-arch · arch-test · coverage · deadcode** — and coverage pulls in
the integration tests. Every OpenSpec `tasks.md` group ends by making this green.

**Run a single test** (add `-tags=integration` for integration/embedded-Postgres tests):

```sh
go test -run TestFaultlineReuseAcrossSBOMs ./internal/knowledge/adapters/store/
go test -tags=integration -run TestFaultlineLifecycleDemo -v ./internal/knowledge/adapters/store/
```

**Regenerate an API** after editing its OpenAPI spec (spec-first — handlers are generated, never
hand-edited): `make generate-api-<context>` (e.g. `generate-api-knowledge`). Specs live in
`api/<context>.openapi.yaml`; the monolith's is `api/openapi.yaml`.

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

The contexts and their pipeline order:

**Kernel/Registry** (shared value objects + Product→Project→Release identity) → **Evidence** (immutable,
content-addressed SBOM/VEX; canonical inventory) → **Knowledge** (Faultline aggregate; order-independent
reconciliation; feed ACLs; correlation) → **Governance** (Findings + append-only Enterprise Positions — AI
proposes, humans/policy decide) → **Communication** (deterministic Publication materialization + serializer
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
  — only adapters + the composition root may import it).
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
framework, **no external broker** — event delivery is a Postgres transactional outbox + relay (a broker can
slot behind the same event envelope later). Standards-only formats: CycloneDX/SPDX in; CycloneDX-VEX /
OpenVEX / CSAF out.

## Key invariants

- **Faultline** = one enterprise card per canonical CVE (own opaque id; the CVE is an alias, normalized from
  distro aliases). Source **Proposals** are append-only (audit); the reconciled view is deterministic by
  source precedence; lifecycle is forward-only (Created→Enriched→Correlated→Mature→Superseded) — a card is
  **never deleted**, only superseded. Duplicate CVE from a later SBOM **reuses** the existing card.
- **VEX overlays, never deletes** — VEX changes effective/enterprise state only; raw findings are preserved.
- **AI is advisory** — the Intelligence Gateway *proposes* a position; humans or policy decide. It is
  disable-able and never auto-decides.

## Scripts & tooling

- `scripts/list-open-vulns.sh` — auto-discovers API key + product ids and lists open vulnerabilities via the
  API, with a day-over-day snapshot diff.
- `scripts/release-smoke-test.sh` — one-command release test (build → fresh DB → migrate → run → register →
  upload the SBOM under `scripts/` → verify components + enrichment). Wrapped by the `/themis-release-test`
  skill.
- Defects and go-forward gaps are tracked in `docs/current-changes/project-backlog.md` (e.g. D-NVD-2,
  D-FEED-2).
