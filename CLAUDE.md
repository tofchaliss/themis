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
  initiative, even after a green `make check`. `gh pr create` and `gh pr merge` are on the **deny** list in
  `.claude/settings.local.json`, beside `rm -rf /` and `git push --force` — that is the enforcement, and it
  is deliberate. Removing it is itself an explicit ask, and it goes back afterwards.
- **Merging a STACK: never `--delete-branch` the base.** Merge the base PR without it, retarget the child
  PR, *then* delete. Deleting the base closes the child instead of retargeting it — and because this repo
  **squash**-merges, the base's original commit is not an ancestor of `main` afterwards, so simply
  repointing the child at `main` makes its diff double-count everything the base already landed.
  Either behaviour alone is recoverable; together they lose the PR and poison the diff (done 2026-08-10 to
  PR #91, recovered as #92). **To recover:** confirm the squash was content-identical
  (`git diff <original-base-commit> <squash-commit>` must be empty — that is what makes the next step
  conflict-free), branch fresh from the merged `main`, cherry-pick the child's commit onto it, and open a
  new PR. Do not reach for `git push --force`; it is denied, and this path does not need it.
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
make vet-tags           # type-check EVERY build tag (integration · e2e · llm · postgres)
make clean-arch         # go-cleanarch: monolith + each greenfield context (see below)
make arch-test          # ./tests/architecture — the Go architecture test
make coverage           # scripts/check-coverage.sh, per-package tiers
make deadcode           # x/tools deadcode (non-fatal reporter, exits 0)

make e2e-evidence       # Evidence context end-to-end (register → upload SBOM → inventory)
make e2e-pipeline       # M5 multi-context pipeline over the event bus (-tags=e2e ./tests/pipeline/...)
make e2e-llm            # Intelligence real-model e2e against a live OpenAI-compatible server
```

`make check` runs: **build · vet-tags · test · lint · clean-arch · arch-test · coverage · deadcode** — and
coverage pulls in the integration tests.

**`vet-tags` exists because a tagged file is invisible to `go build`, `go vet` and the test run unless
its tag is set, so it rots silently.** Found 2026-08-07: `llm_e2e_test.go` had not compiled since the
T10 refactor renamed the read seam — the repository's only real-model test was dead code for days, and
nothing noticed because no gate ever set `-tags=llm`. It is type-check only (no execution), and it
caught two more stale tagged callers within the hour. Every OpenSpec `tasks.md` group ends by making this
green. `make check-ci` is the
same gate but swaps `coverage` for `coverage-greenfield` (go-forward tree only); it — not `make check` — is
what `.github/workflows/{pr,main}.yml` enforce, because the frozen v0.3.x legacy integration tests are green
only on macOS's coarse clock.

`make e2e-llm` is **opt-in** (`//go:build llm`, excluded from `make check`): it drives
`recommend_position`, **`plan_remediation` and `explain_vulnerability`** against a real OpenAI-compatible endpoint and needs
`THEMIS_LLM_URL` / `THEMIS_LLM_MODEL` (plus
`THEMIS_LLM_API_KEY` and `THEMIS_LLM_RESPONSE_FORMAT=json_schema` for servers like LM Studio that require a
bearer token and reject `json_object`); it skips if the endpoint is unreachable. See `TESTING.md`.

It guards a defect class `make check-ci` **cannot** see: the prompt and the Grounding Verification gate
are an interface with no compiler between them, and a fake provider returns whatever the test author
already believed. Measured 2026-08-07 — every fake-provider test passed while the live
`plan_remediation` capability was refused **three times running**, each for a citation form the prompt
had invited and the gate rejected. A 204 whose reason is `business_invalid` therefore FAILS the test:
a declined recommendation is the seam working, an ungrounded citation is the two halves disagreeing.
**THREE deadlines govern one recommendation, and the SHORTEST decides** — raising one alone changes
nothing (AI-TIMEOUT-1, measured 2026-08-07):

1. `THEMIS_INTELLIGENCE_TIMEOUT` on the **Governance** node — how long it waits for a recommendation.
2. `THEMIS_LLM_TIMEOUT` on the **Intelligence** node — the provider HTTP client **and** the Gateway's
   per-invocation runaway guard (one variable drives both, so they cannot disagree).

Both default to `60s`. For a slower or larger local model, **raise both**: with only the Intelligence
side raised, Governance hangs up first, the Gateway sees its request context cancelled mid-provider-call
and logs `provider_error` — so a caller-side timeout is misread as an Intelligence fault. Three calls
aborting at 59.99s with `THEMIS_LLM_TIMEOUT=300s` set is exactly what that looks like.

A no-proposal `204` now states its cause on `X-Themis-AI-Reason` (AI-204-1): `disabled` · `unreachable` ·
`insufficient` (the model correctly declined — the seam working) · `provider_error` · `business_invalid`.
Before that, all of them read as "the AI declined".

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

- **Topology: one Postgres server, up to seven databases** — `evidence` (the `registry` schema **co-locates**
  here), `knowledge`, `governance`, `communication`, `bus`, `auth` (the shared API-key store; see the auth
  switch below), and `intelligence` (the Δ3a **Operational Semantic Index** — Intelligence's own KS2 vector
  store; present only when semantic precedent is enabled via `THEMIS_DATABASE_DSN` on the Intelligence node —
  it is derived/rebuildable, not truth, so the Gateway still owns no truth). Ports: Evidence `:8081`, Registry `:8082`,
  Governance `:8083`, Communication `:8084`, Intelligence `:8086`, and **Knowledge `:8085`** — which is now
  also its code default (it used to default to `:8082` and collide with Registry; fixed 2026-08-07).
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
- **Registry self-migrates** into the shared `evidence` DB (`THEMIS_REGISTRY_MIGRATE=1`) as of 2026-08-07.
  It keeps its own `registry_schema_migrations` bookkeeping table, so it no longer reads Evidence's version
  and silently skip its own `CREATE TABLE`s. Give it the **plain** DSN: the migrations-table parameter is
  attached internally to a separate migration DSN, because pgx forwards an unknown DSN parameter to Postgres
  and every runtime connection would fail. Loading the SQL by hand still works and remains idempotent.
- **Drive an SBOM:** `scripts/gf-upload-sbom.sh` registers Product→Project→Release and uploads (auto-detects
  CycloneDX/SPDX; streams large files via `curl --data-binary @-`; `-r` reuses a release). Evidence is
  content-addressed, so re-uploading byte-identical content to the same release **dedups**, and the
  same bytes pointed at a different release refuse loudly with 409 (EDR-EVIDENCE-01 D3 note) — a
  re-run needs changed bytes.
  A **scanner report** (`kind:"scanner-report"`, curated per-finding JSON with the component each finding
  names — see TESTING.md) uploads through the same endpoint and folds + matches at scanner (Asserted)
  trust (KN-SCAN-1). Discovery otherwise runs at upload time only; the **re-discovery sweep**
  (KN-RECOR-1, default ON, `THEMIS_REDISCOVERY_*`) re-runs it for the stalest correlated releases so a
  CVE published after a release's last upload still reaches its inventory.
- **Opt-in enrichment** (off by default — no silent outbound calls; all **relevance-bounded** per
  EDR-KNOWLEDGE-01 D5, i.e. feeds enrich *existing* Faultlines and never mirror the full feed):
  `THEMIS_NVD_ENABLED=1` (authoritative CVSS/severity via the modified-since watch),
  `THEMIS_EPSSKEV_ENABLED=1` (EPSS/KEV/ExploitDB signal sweep),
  `THEMIS_REDHAT_ENABLED=1` (per-CVE Red Hat vendor severity + `not_affected` applicability + RPM fixed-version
  bounds; covers RHEL/Rocky/Alma — EDR-VEX-01 Phase 3),
  `THEMIS_ALPINE_ENABLED=1` + `THEMIS_ALPINE_BRANCHES=<v3.20,…>` (Alpine secdb fixed apk version bounds; the
  branch DB is fetched whole and uncarded records discarded in memory — EDR-VEX-01 D7), and
  `THEMIS_VEXFEED_ENABLED=1` + `THEMIS_VEXFEED_URLS=<csaf-base,…>` (generic per-CVE CSAF-VEX directories at
  `<base>/<year>/cve-<id>.json` — EDR-VEX-01 B4). Each feed also honors `_URL`/`_POLL_INTERVAL` (default 12h).
  OSV distro + language correlation is always on, and records per-distro feed-health rows
  (`osv/alpine`, `osv/rocky`, … — informational tier, so a quiet distro never reads as degraded).

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
the unique customers a release reaches — C1; plus the `GET /products` → `/products/{id}/projects` →
`/projects/{id}/releases` traversal, so a posture is reachable by name instead of only by a UUID somebody
captured at upload — DASH-1) → **Evidence** (immutable,
content-addressed SBOM/VEX; canonical inventory) → **Knowledge** (Faultline aggregate; order-independent
reconciliation; feed ACLs; correlation) → **Governance** (Findings + append-only Enterprise Positions — AI
proposes, humans/policy decide; triage priority is `base_score × blast-multiplier`, the multiplier derived
from Registry's blast-radius over the read seam `THEMIS_REGISTRY_URL`, **fail-safe to 1.0** when Registry is
unreachable, and saturating to 2.0× at `THEMIS_BLAST_RADIUS_CAP` unique customers (default 10) — C2.
A suppressing decision (`not_affected` / `accepted_risk`) records **the premise it rested on** — the
exploit signals at decision time, and an optional `review_by` date — and a **disposition watcher**
re-surfaces it via `governance.disposition_stale.v1` when that premise drifts (a CVE enters KEV, an
exploit becomes public, EPSS rises past `THEMIS_EPSS_DRIFT_THRESHOLD`) or the review date passes. It
**never changes the Position**: it re-opens the QUESTION, so an acceptance does not vanish — it expires.
That watcher is the safety net under `residual_priority`, which removes a suppressed Finding from the
queue — GOV-14b) →
**Communication** (deterministic Publication materialization + serializer
registry). Beside the pipeline sits **Intelligence** — a reactive AI Gateway; all provider/LLM code is
confined here behind a provider port (`internal/intelligence/adapters/`), it has no truth-store driver, and
it reads via read APIs / writes via proposal-intake.

Three capabilities ship, and their **output classes** decide everything about the path they take (T7):
`recommend_position@v1` is a **Decision** capability over one Finding — its stance aspires to become an
Enterprise Position, so it enters Governance as an advisory proposal on `inferred` evidence that no policy
may auto-accept. `plan_remediation@v1` (Information, one Release) and `explain_vulnerability@v1`
(Information, one Finding — GUI-1: what the flaw means for THESE components, grounded on the stored CVE
summary, which it overlays and never replaces) are **Information** capabilities — ephemeral, proposing no
stance, so nothing reaches Governance and there is nothing to accept. That is what makes them safe to add:
the worst outcome of a wrong plan or explanation is a human disagreeing with it. The plan's GROUPING
(231 Findings → ~12 package upgrades) is a deterministic `GROUP BY` computed before the prompt — the model
is asked only for what needs judgement.

**Semantic retrieval is a service with two consumers, not a step inside the AI path** (`app.PrecedentService`).
The Gateway grounds `recommend_position` on it, and `GET /findings/{id}/similar` serves the *same instance*
to a security engineer with **no model in the path** — same question, one answer, whoever asks. Two rules
keep it small: **filters are query semantics** and live inside the search (`include_same_release`), while
**redaction is an output boundary** applied at each consumer's edge (a prompt and an HTTP response are
different exits) — and redaction is a projection, never an edit to the stored Position. The service owns
the ordering rule that used to be implicit: semantic neighbours first, the exact-CVE fallback **only** when
semantic found nothing. Every failure degrades to no-precedent; a missing precedent never blocks a
recommendation or a page load. Contradictory precedent is why `recommend_position` honestly returns
`insufficient` — and is exactly what the human endpoint exists to show.

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
dedicated `bus` database (`internal/platform/eventbus`); a broker can slot behind the same event envelope
later. Standards-only formats: CycloneDX/SPDX in; CycloneDX-VEX /
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
- **A distro advisory's package list is SCOPE, not N vulnerability claims** (EDR-CORRELATION-01). A
  module-stream advisory rebuilds every RPM in the stream and lists them all as affected; read as N
  claims, a CPython flaw becomes a vulnerability of `python3-pyyaml`. Each matched component
  therefore carries a **`claim_class`** — `carrier` (evidence says it carries the flaw), `scope` (it
  was in the rebuild set), or empty = `unknown`. **Unknown is treated as `carrier` everywhere**: a
  gap in attribution evidence must never hide a live vulnerability. Nothing is dropped — replacing a
  superseded build is real work — but a remediation plan and the AI's grounding use carriers only.
  Carrier products come from NVD's CPE configurations and from non-distro OSV records; a distro
  record cannot supply them.
- **AI is advisory** — the Intelligence Gateway *proposes* a position; humans or policy decide. It is
  disable-able and never auto-decides. Its spend is bounded per capability per window
  (`THEMIS_INTELLIGENCE_BUDGET_TOKENS`/`_WINDOW`; unset = unlimited, which is the default because a
  budget switched on by accident is indistinguishable downstream from an AI outage).
  **Model tiers are runtime Gateway decisions** (phase3-intelligence-router; callers never name a
  model — INT-0062): an honest `insufficient` on a Decision capability retries ONCE on
  `THEMIS_INTELLIGENCE_MODEL_ESCALATION` (never on schema/business failures — those are contract
  problems, and escalating would mask which lever to pull — nor on timeouts); a nearly-spent budget
  window degrades to `THEMIS_INTELLIGENCE_MODEL_ECONOMY` instead of refusing (exhaustion still
  refuses). Both tiers optional; a tier model equal to the primary is treated as unset.

## Scripts & tooling

- `scripts/list-open-vulns.sh` — auto-discovers API key + product ids and lists open vulnerabilities via the
  API, with a day-over-day snapshot diff.
- `scripts/release-posture.sh` — the **consolidated release posture** from the CLI: sorts a release's
  Findings by `residual_priority` (D14 — intrinsic severity scaled by what was decided), joins Knowledge for
  the exploitability band and the published fix version, and with `--ai N` asks the Gateway to recommend a
  position for the top N undecided Findings. Read-only over the existing APIs; it stores nothing and adds no
  workflow, so a future GUI calls exactly the same endpoints. It is also the working spec for DASH-1/DASH-2 —
  what it has to do by hand (supply a release UUID; one Knowledge call per Faultline for the severity band)
  is precisely what the read surface is missing.
- `scripts/vm-verify.sh` — **one read-only report** for a running deployment: unit states, migration
  versions, pipeline counts, bus reader lag, feed proposals, carrier-attribution coverage, AI
  invocation reasons, and (with a release id) a posture sample. Replaces the five or six
  hand-written one-liners that verification used to take, which is where the mistakes lived. The
  EXPECTED migration version is read from the migrations directory, never hard-coded — a literal
  would be right the day it was written and silently wrong after (the defect that left the systemd
  installer loading only the first registry migration). Strictly read-only: mutations stay in a
  human's hands. `PGBASE=… ./scripts/vm-verify.sh [RELEASE_ID]`.
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

## Shell commands the user pastes (paste-safe, ALWAYS)

The user runs the commands I give **by pasting whole fenced blocks** into a `fish` shell on the VM (and
sometimes locally). Two rules are mandatory, not stylistic — breaking them makes the paste error out
mid-run:

- **Every interstitial comment INSIDE a fenced code block MUST begin with `#`.** Any explanatory prose left
  between commands in a block is executed as a command when pasted and errors (e.g. a line starting with
  `(` → a fish syntax error; `then re-fire…` → `command not found`). If a step needs prose, put it OUTSIDE
  the fence, or make it a `# comment` line inside. Never leave a bare sentence inside a ``` block.
- **`fish` does NOT support the bash `VAR=value command` prefix, and `make` may not inherit exports.** To
  set env for one command in any shell, use `env VAR=value … command` (e.g.
  `env THEMIS_LLM_URL=… THEMIS_LLM_MODEL=… go test -tags=llm …`), not `VAR=value make …` (measured
  2026-08-24: the prefix was silently dropped and the test ran on defaults). Multi-line `set -x VAR value`
  before the command also works.

Also standing (see the session-specific guidance): the VM `bash`/`fish` may have `noclobber` — overwrite a
file with `rm -f file` then recreate, not `>|`; keep straight quotes; keep blocks short and bannerless.

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
