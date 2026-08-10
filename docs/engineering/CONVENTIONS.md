# Phase-3 Greenfield — Cross-Cutting Engineering Rules

**Updated:** 2026-07-15 · **Read with `STACK.md` before any `/opsx:apply`.** These are rules **every node**
(each deployable context/service — Registry, Evidence, Knowledge, Governance, Communication, Intelligence)
follows, independent of any single OpenSpec change. They are not per-change tasks; they are standing
conventions. **ADR wins.** New cross-cutting rules are added here (R1, R2, …).

## R1 — Every node logs to the console AND to OpenTelemetry

Dual observability, always on. **Each node emits both**, wired identically from one shared observability
package (never per-context bespoke logging):

- **Console** — structured logs to stdout via **`zap`**; human-readable in dev, JSON in prod. This is the
  **local-debug** channel.
- **OpenTelemetry** — traces + metrics + logs to the configured OTel exporter. This is the **architectural
  telemetry**, correlated by **stable business identifiers** (not infra ids).

Rules:

- Both channels are available in **every environment**; which exporters are active is **config-driven**
  (R2). Console is the local-debug artifact; OTel is the telemetry system-of-record — BCK-0051 explicitly
  distinguishes debug logs from architectural telemetry.
- **No raw `fmt.Print*` / ad-hoc printf as telemetry.** All output goes through the structured logger.
- **Redact before emitting** — secrets, PII, and confidential enterprise data never appear in the clear in
  either channel (INT-0064/0069).
- Every significant operation carries a **correlation id** so a workflow can be reconstructed across nodes
  (BCK-0051).

Grounded in **BCK-0051** (observability = architectural capability: structured logs + metrics + traces +
correlation ids) and **INT-0064**; consistent with `EDR-INTELLIGENCE-01` D9 (OpenTelemetry + console
debug), generalized to all nodes.

**Realized by `internal/platform/observability`** (2026-07-18): one `Setup(ctx, Config)` builds a **zap**
logger whose core **tees** to stdout (console/JSON) **and** an OTel `LoggerProvider` via the `otelzap`
bridge — a single `log.Info(…)` emits a console line **and** an OpenTelemetry log record. The level, console
format, and OTLP endpoint are read by `ConfigFromEnv` (`THEMIS_LOG_LEVEL` / `THEMIS_LOG_FORMAT` /
`THEMIS_OTLP_ENDPOINT` — `THEMIS_OTLP_LOGS_ENDPOINT` still honored as a fallback — / `THEMIS_OTLP_INSECURE`);
OTel export is on only when an endpoint is set. A `RequestLogger` middleware logs every HTTP request with a
correlation id.

**All three signals are now live (2026-08-07).** Metrics (2026-08-06) are a Prometheus registry scraped at
`/metrics`; **traces** are an OTLP `TracerProvider` with a server span per HTTP request. Two deliberate
choices:

- **The span is named after the route pattern, not the raw path** — `GET /api/v1/findings/{id}`, not one
  span name per finding id. Because chi only fills its `RouteContext` *during* routing, the middleware names
  the span provisionally and **renames it after the handler returns**; naming it up front would have
  produced `GET other` for every request.
- **Every span carries `themis.correlation_id`**, the same id the log line carries — that shared key is what
  makes a trace and its logs joinable. A trace without it is a latency chart; with it, it is an
  investigation.

**Metrics are pull, traces are push**, on purpose: a counter survives having no collector (it accumulates
until someone scrapes) while a span does not (it has no pull model), so metrics stay useful on an isolated
node and traces cost one exporter dependency rather than two. The pure `domain`/`app` rings never
log (enforced by depguard — only adapters + the composition root import the package), so the package sits at
the platform layer, outside any bounded context. **All six** greenfield nodes
(`cmd/{registry,evidence,knowledge,governance,communication,intelligence}`) wire it at startup and each
mounts `/metrics`; example config in `deploy/node.env.example`.

## R2 — Configuration is self-documented in the config file, with comments

Configuration documentation lives **in the config file itself**, as inline comments — there is **no
separate config reference doc** that can drift out of sync.

Rules:

- **Every option carries an inline comment** stating: what it controls, its type + units, the **default**,
  and valid values / range.
- Each node ships a **fully-commented example config** (e.g. `config.example.yaml` and/or `.env.example`)
  covering **all** of its options — e.g. DB DSN, HTTP address, **OTel exporter endpoint + on/off**, **log
  level + format** (R1), plus node-specific options (Intelligence budget/pool sizes + provider clearance;
  Knowledge feed endpoints; Communication channels; etc.).
- **Secrets are referenced, never inlined** — the example names the env var (or secret ref), never a real
  value.
- The commented example config is the artifact a reviewer reads to understand every knob; keep it current
  as options are added.

## R3 — Aggregate reads inside an event handler join the ambient inbox transaction

An inbound event handler runs its writes inside the consumer **inbox unit of work** (the exactly-once
transaction, EB-06). Any aggregate **read** it performs — including the re-load in an optimistic
load-apply-save retry — **must run on that same transaction**, not on the pool. Route reads through the
store's `querier(ctx)` seam (returns the ambient tx when one rides the context, else the pool); the write
seam is `Save` / `exec(ctx)`.

**Why:** when one envelope mutates the *same* aggregate more than once (e.g. a `faultline_enriched` that
both re-prioritizes and folds a VEX applicability onto one Finding), a committed pool-read cannot see the
first mutate's uncommitted version bump, so the optimistic `WHERE version = prev` matches zero rows and
`ErrConcurrent` **never converges** — the reader poison-halts the whole stream (D8). This is the third
symptom of one root tension — the D7 correlation-tx stall, the PR #59 Knowledge shared-CVE halt, and the
Governance enrichment halt (BUG-1). Treat "handler reads on the pool" as a defect.

**Guard:** each context's store owns a regression test that mutates one aggregate twice within a single
inbox envelope and asserts convergence (e.g. Governance's `TestInboxTwoMutationsOnOneFindingConverge`).

## How these apply per node

Both rules are **shared infrastructure**, not re-implemented per context: one observability bootstrap
package (R1) and one config-loading convention (R2) that every node imports. A node's `main`/bootstrap
wires the shared logger + OTel from its commented config at startup, before serving.
