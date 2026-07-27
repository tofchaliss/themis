# Design — phase3-event-infrastructure (Event Infrastructure / M5 — the platform event bus)

## Source of truth

Every decision here traces to **`docs/engineering/decisions/EDR-EVENTBUS-01.md` (D1–D11)** and its seed
`EDR-KERNEL-01` D4. This document is the how; the EDR is the why + the rejected alternatives. The **governing
principle** throughout: *freeze contracts early; evolve implementations later* — each item locks an observable
behaviour now and lets the mechanism mature without changing the contract.

## Scope (this change)

The platform-owned channel between the existing per-context outboxes and the existing inbound consumers, plus
the end-to-end wiring that lets one SBOM flow through all four contexts as events and emerge as a published
OpenVEX artifact. The producing/consuming ends already exist; M5 builds the transport and threads the
envelope through it.

## Topology (D3 / D4)

- **One PostgreSQL server; database-per-context + a dedicated `bus` database.** Each context owns its database
  (aggregates + outbox + inbox); the `bus` database holds the platform event log. A Postgres database is a
  hard boundary (no cross-database joins/transactions, no dblink/FDW) — so split-stability is **structural**,
  not disciplinary: a consumer physically cannot read another context's tables.
- **Outbox and event log are two tables in two databases, bridged by the relay** (forced by D1–D3 + BCK-0041):
  producer `<ctx>_outbox` (own DB, atomic with the aggregate) → relay → `bus.event_log` (platform DB, the
  channel = Postgres stand-in for a Kafka topic).

## Delivery semantics (D5 / D6 / D7 / D8)

- **Exactly-once application (D5).** The transport is at-least-once (BCK-0049). Correctness is the consumer's:
  a durable **inbox** (`processed_events`, keyed by envelope-id) in the consumer's own DB, written in the
  **same transaction** as the business apply → a redelivered envelope is a no-op. The **cursor/offset** over
  `bus.event_log` is a Postgres-era read optimization only (no correctness; replaced by the broker offset
  under Kafka).
- **Per-subject ordering (D6).** The platform guarantees ordered delivery for events with the same
  `Envelope.Subject`; **no** global or cross-context ordering. PostgreSQL realizes it via a single monotonic
  `event_log` sequence (one cursor); Kafka via partition-by-`Subject`. Producers stamp `Subject` = the
  aggregate whose order matters. Cross-context ordering is unnecessary (linear DAG); a future fan-in is a saga
  on `Envelope.CorrelationID`.
- **Stream + interest set + gap-free drain (D7).** A consumer **subscribes to a stream** (routing + ordering
  unit; one stream per producing context today) and declares an **interest set** (dispatch filter; the
  existing `Handle` ignore-unknown). Routing/ordering (stream) is separate from dispatch (interest). The drain
  loop is **gap-free by observable contract** — no event that will become visible is skipped (the inbox guards
  duplicates, not gaps); the mechanism (a commit-order / txid watermark) is an implementation choice.
- **Failure isolation (D8).** Transient failures retry with backoff indefinitely (durable). Permanent/poison
  failures are surfaced, never silent-skip, and block only the affected `Subject`. Replay reuses the original
  envelope so D5 holds. **Staged:** architectural target = subject-level isolation; **M5 implementation =
  stream-halt with loud alerting**; migration = single drain loop → subject-aware scheduler, no contract
  change.

## Envelope + integration contract (D9)

- **Full `Envelope` threaded end-to-end** (id, type, occurred-at, source_context, subject, schema_ref,
  correlation_id, payload): the outbox stores it, the relay copies it to `bus.event_log`, the reader hands it
  to `Consumer.Handle`. Knowledge's `FaultlineID` generalizes to `Subject`; `source_context` / `schema_ref` /
  `correlation_id` are added. This is M5's largest change to the existing seams.
- **What crosses the wire is a producer-owned integration event** named by `schema_ref`, not the raw domain
  struct (BCK-0046). M5 **freezes the current payload shapes as v1**, each pinned to a `schema_ref` and
  guarded by a **contract test** (produced payload validates against a checked-in JSON schema) — so a domain
  refactor that reshapes the wire fails the test instead of silently breaking a consumer. Explicit DTOs are
  the deferred maturation; the mapping lives in the producer's **outbound** adapter.

## Layout (D10) — house context-first, additive; platform is business-agnostic

- **`internal/platform/eventbus`** owns transport infrastructure: `bus` store + migrations, `Publisher`,
  stream `Reader` / drain engine, scheduling, retry policy, transport mechanics. Depends **only** on the
  kernel (`Envelope`) + drivers — never a bounded context. Depguard-restricted to adapters + `cmd`, exactly
  like `internal/platform/observability`. go-cleanarch treats it as shared infra (the observability
  precedent), not a context.
- **Each context keeps its messaging semantics:** outbox, relay (inject the real `Publisher`), `Consumer.Handle`,
  inbox (`processed_events` in its own DB), and subscription declarations (stream + interest set).

## Composition + binaries (D10)

- Each context's `cmd` runs its relay + its reader(s): `evidence` (relay only) · `knowledge` (relay + reader
  on the evidence stream) · `governance` (relay + reader on knowledge) · `communication` (relay + reader on
  governance). **M5 adds the missing `cmd/knowledge`.**
- **Production = one binary per bounded context.** Dev + e2e MAY use a **composed in-process runner** wiring
  all contexts against one embedded PostgreSQL server (N context DBs + the `bus` DB) — a developer
  convenience, not a deployment model.

## Definition of Done (D11)

M5 is complete when an SBOM can be ingested and a publishable **OpenVEX** artifact is eventually produced using
**only asynchronous event-based communication** between contexts, with **no synchronous cross-context
orchestration** (read-only read-API queries — e.g. Knowledge reading Evidence's inventory — remain permitted;
data reads are not workflow causation). Proven by:

- **one black-box pipeline e2e** (`tests/e2e/pipeline_e2e_test.go`, `//go:build e2e`, `make e2e-pipeline`) —
  drives the SBOM upload, observes the OpenVEX artifact, asserts eventual appearance with the expected stance
  under a timeout, zero internal-state peeking;
- **three focused platform tests** — D5 idempotency (redeliver → no duplicate), D6 ordering (Enriched before
  Superseded honored), D8 poison-halt (loud, never silent);
- **a static architectural assertion** — the arch-test/depguard already forbid a context importing another's
  `app`/`domain` (only the read-API client seam + eventbus), so synchronous orchestration is structurally
  impossible.

## What is additive vs the existing seams (no rewrites)

- The **outbox tables + relays** stay; the relay just receives the real `Publisher` instead of `logPublisher`.
- The **inbound `Consumer.Handle`** stays as the ACL; it evolves to carry the `Envelope`, and its
  ignore-unknown behaviour becomes the named interest set.
- The **kernel `Envelope`** is finally threaded (it already exists; nothing about it changes).
- New surface: the `internal/platform/eventbus` package, the `bus` database, per-context inbox tables,
  `cmd/knowledge`, the in-process runner, and the e2e/platform tests.

## Stack

No new third-party dependency and no external broker (see `docs/engineering/STACK.md`, "Event infrastructure
(M5)"): PostgreSQL via `pgx/v5`, `golang-migrate/v4` for the `bus` + inbox migrations,
`santhosh-tekuri/jsonschema/v6` for the integration-contract v1 guard (already in the tree), OpenTelemetry +
`zap` for the drain-loop meter/alerts, `fergusstrange/embedded-postgres` for the e2e. A broker can slot behind
the same `Envelope` later (D1/D2).

## Quality gates

The six Themis gates (`make check`: build · lint · clean-arch · arch-test · coverage · deadcode) per task
group, extended to `internal/platform/eventbus` and the new per-context inbox/subscription code. Coverage
tiers registered in `scripts/check-coverage.sh` + Makefile `COVERAGE_PKGS`; the `bus` and inbox migrations
carry up/down reversibility. The `e2e`-tagged pipeline test runs via `make e2e-pipeline` (opt-in, outside
`make check`), matching the existing `e2e-evidence` pattern.
