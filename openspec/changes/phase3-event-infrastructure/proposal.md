# Proposal — phase3-event-infrastructure (Event Infrastructure / M5 — the platform event bus)

## Why

The four pipeline contexts (Evidence → Knowledge → Governance → Communication) are all built and gated, and
every seam is in place: each context writes to its own **transactional outbox** in the same commit as the
aggregate, a **`Relay`** drains it, and every consuming context has an inbound anti-corruption
**`Consumer.Handle`**. But the only `Publisher` that exists is a **logging stand-in** — so an event reaches
the edge of its producing context and evaporates. Nothing carries it to the context that consumes it.

M5 delivers the missing middle: a **platform-owned communication channel that neither producer nor consumer
owns** (the Kafka ownership model — producer → topic → consumer — realized in PostgreSQL first). It is the
piece that unblocks the single wired **SBOM → published-VEX** end-to-end pipeline, which the per-context
tests and seam tests already validate in isolation but which has never run connected.

Grounded in **`docs/engineering/decisions/EDR-EVENTBUS-01.md` (D1–D11)** — the source of truth for every
decision, rejected alternative, and staged commitment referenced below — and its seed `EDR-KERNEL-01` D4 (the
kernel provides the behavior-free `Envelope`; the outbox runner + relay + bus are M5).

## What changes

- **`internal/platform/eventbus`** — a shared platform package (peer of `internal/platform/observability`)
  owning the **transport infrastructure**: the `bus` event-log store + migrations, the real **`Publisher`**
  (append an `Envelope` to the log), and the **stream `Reader` / drain engine** (gap-free read, per-consumer
  cursor, D8 policy). Depends only on the kernel `Envelope` + drivers; depguard-restricted to adapters + `cmd`.
- **A dedicated `bus` database** on the shared PostgreSQL server; each context keeps its **own** database
  (aggregates + outbox + inbox) — database-per-context makes split-stability structural (D3).
- **The full kernel `Envelope` threaded end-to-end** (outbox → `bus.event_log` → `Consumer.Handle`); D5/D6/D7
  all key on envelope fields (D9).
- **Integration-contract v1 freeze** — what crosses the wire is a producer-owned, `schema_ref`'d contract
  guarded by a contract test, not the raw domain struct (BCK-0046 / D9).
- **Per-consumer inbox** (`processed_events`) giving **exactly-once application** on an at-least-once
  transport (D5); **per-subject ordering** (D6); **stream + interest-set** subscription with **gap-free**
  drain (D7); **subject-scoped failure isolation**, shipped as stream-halt-with-alert for M5 (D8).
- **`cmd/knowledge`** (the one missing composition root) + wiring of relays + readers in each `cmd/*`; an
  **in-process composed pipeline runner** for dev/e2e (a developer convenience, not a deployment model — D10).
- **The black-box `SBOM → OpenVEX` pipeline e2e** + three focused platform tests (D5/D6/D8) + the static
  architectural assertion that there is no synchronous cross-context orchestration (D11).

## Non-goals (deferred / later)

- **External broker (Kafka/NATS)** — the transport is a swappable adapter behind stable ports (D1); the
  broker slots in later with no domain/app change. Postgres channel now.
- **Subject-aware scheduler** — D8's architectural target; M5 ships the simpler **stream-halt-with-alert**
  first cut. Migration path is a drain-loop swap with no contract change.
- **Explicit integration DTOs** — D9 freezes the current shapes as schema-guarded **v1**; the hand-written
  mapping layer is the deferred maturation.
- **Multi-worker per-consumer parallelism** (would partition by `Subject`, D6) — M5 is single drain loop.
- **An all-in-one production binary** — production stays one binary per bounded context (D10).

## Realizes (ADRs / EDR)

- **EDR:** `EDR-EVENTBUS-01` D1–D11 (source of truth); seed `EDR-KERNEL-01` D4.
- **Collaboration:** CON-0012 (event-driven collaboration), CON-0014 (capability separation), CON-0016
  (traceability).
- **Event architecture:** BCK-0040 (persistence never publishes), BCK-0041 (publish only after commit →
  outbox), BCK-0046 (integration events are stable contracts, distinct from domain events), DOM-0033 (events
  are completed facts).
- **Reliability:** BCK-0049 (idempotency; exactly-once *delivery* rejected → exactly-once *application*),
  BCK-0044 (orchestration coordinates, does not own behavior).

## Ground rules

ADR/EDR wins; the legacy `internal/` PoC is frozen reference. System of record = this change's `tasks.md`.
This is a `phase3-*` change: proposal/design/tasks with the EDR as source of truth and **no `specs/` deltas**
(so `openspec validate` reporting "no deltas" is expected; archive with `--skip-specs`). M5 adds **no external
broker and no new third-party dependency** — PostgreSQL only. Each task group ends by making the six Themis
gates (`make check`) green, extended to the new packages.
