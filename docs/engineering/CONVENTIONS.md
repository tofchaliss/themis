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
`THEMIS_OTLP_LOGS_ENDPOINT` / `THEMIS_OTLP_INSECURE`); OTel export is on only when an endpoint is set. A
`RequestLogger` middleware logs every HTTP request with a correlation id. The pure `domain`/`app` rings never
log (enforced by depguard — only adapters + the composition root import the package), so the package sits at
the platform layer, outside any bounded context. Each greenfield node (`cmd/{evidence,registry,governance,
communication}`) wires it at startup; example config in `deploy/node.env.example`.

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

## How these apply per node

Both rules are **shared infrastructure**, not re-implemented per context: one observability bootstrap
package (R1) and one config-loading convention (R2) that every node imports. A node's `main`/bootstrap
wires the shared logger + OTel from its commented config at startup, before serving.
