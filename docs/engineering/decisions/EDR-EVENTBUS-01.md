# EDR-EVENTBUS-01 — Event Infrastructure (M5) Realization

Status: **Grilled — ready for issue breakdown** (11 decisions locked)
Date: 2026-07-25
Author: architecture grilling session

## Purpose

Engineering Decision Record for **Event Infrastructure (Phase-3 sprint M5)** — the platform-owned transport
that actually carries an integration event from the context that produced it to the contexts that consume it.
It resolves the forward dependency left open by `EDR-KERNEL-01` (D4, the "M5-seed"): the kernel provides only
the behavior-free **envelope** contract; the **outbox runner + relay + event bus** are behavior and belong to
this shared platform, not the kernel. Ground rule: **ADR wins; the PoC (`internal/`) is reference only.**

The per-context ends already exist and are tested: every context writes to its own **transactional outbox**
in the same commit as the aggregate, a **`Relay`** drains it, and every consuming context has an inbound
**anti-corruption `Consumer.Handle(eventType, payload)`**. The only missing piece is the **platform channel in
the middle** — today the sole `Publisher` is a logging stand-in, so events reach the edge of the producing
context and evaporate. M5 replaces the stand-in with a real channel, which is what unblocks the single wired
**SBOM → published-VEX** end-to-end pipeline.

## Realizes (ADR traceability)

- **Collaboration:** CON-0012 (event-driven collaboration between contexts; rejects shared database and
  direct service invocation), CON-0014 (business capability separation), CON-0016 (complete traceability)
- **Event architecture:** BCK-0040 (persistence preserves state, never publishes), BCK-0041 (publish only
  after successful persistence → transactional outbox), BCK-0046 (integration events are stable collaboration
  contracts, distinct from domain events), DOM-0033 (domain events represent completed business facts)
- **Reliability:** BCK-0049 (idempotency across distributed processing; **exactly-once delivery is rejected**
  as an infrastructure guarantee — consumers must be idempotent), BCK-0044 (orchestration coordinates but does
  not own behavior)
- **Seed:** `EDR-KERNEL-01` D4 (envelope in kernel, machinery in M5); `STACK.md` line 55 (Postgres-outbox +
  relay, no external broker to start; a broker slots behind the same envelope later)

## Grilled against (current-state slice)

`internal/kernel/event` (the `Envelope` contract + JSON schema); each context's
`adapters/store/relay.go` (`Relay` + `Publisher` port + `OutboxNote`) and `<ctx>_outbox` migration;
`internal/{governance,communication}/adapters/inbound/consumer.go` (the `Handle` ACL seams); the
`logPublisher` stand-ins in each `cmd/<ctx>/main.go`.

---

## Headline architectural invariant

There is a **platform-owned communication channel that neither producer nor consumer owns.** Bounded
contexts own business state; the Platform owns message transport; **consumers never reach into another
context's persistence.** This is the Kafka ownership model (producer → topic → consumer; nobody owns the topic
but the messaging infrastructure), realized in Postgres first.

## Governing principle — freeze contracts early; evolve implementations later

Every decision below locks an **observable/contractual behaviour now** and lets the **mechanism mature later
without changing the contract.** Completing a contract later is *not* adding a new architectural capability —
it is finishing an existing one. This principle is the connective tissue of the EDR:

| Decision | Contract (frozen now) | Implementation (matures later) |
| --- | --- | --- |
| D1/D2 | outbox + two stable ports carrying the `Envelope` | Postgres channel → Kafka (adapter swap) |
| D5 | exactly-once **application** via the consumer inbox | cursor now → broker offset under Kafka |
| D7 | gap-free consumption of the stream | the watermark/algorithm that achieves it |
| D8 | failures isolate to the smallest boundary (`Subject`) | stream-halt now → subject-aware scheduler |
| D9 | `schema_ref`'d integration contract on the wire | domain-struct freeze now → explicit DTOs |

## Decisions (resolved)

### D1 — Transport is a swappable adapter behind two stable ports (EB-Q1)

The transport is hidden behind **two stable ports carrying the kernel `Envelope`**: an outbound `Publisher`
(the relay calls it; it never knows the destination) and an inbound reader that feeds the existing
`Consumer.Handle`. **Domain, app, and the business adapters never reference the transport.** Moving from the
Postgres channel to Kafka later changes **only these two transport adapters plus composition wiring** — never
domain/app, the outbox, the relay loop, or `Handle`.

**ADR consistency:** BCK-0046 (the envelope is the stable integration contract across both transports) ✓;
CON-0012 (collaboration by published facts, not direct invocation) ✓; realizes KERNEL-D4 (envelope in kernel,
machinery here) ✓.

*Rejected:* baking the transport into app/adapters (forces a rewrite at the Kafka move); synchronous HTTP push
between contexts as the primary channel (reintroduces the direct-service-invocation coupling CON-0012 rejects,
and couples publisher availability to consumer availability).

### D2 — The transactional outbox is permanent, independent of transport (EB-Q1)

The outbox is **not** a Postgres-era scaffold. You cannot atomically write an aggregate to Postgres **and**
publish to Kafka in one transaction, so even in the Kafka era the pattern stays: **commit to the outbox in the
aggregate's transaction, then a relay ships from the outbox to the channel.** Kafka replaces only the
`Publisher`'s destination and the inbound reader — never the outbox, the relay loop, or `Handle`.

**ADR consistency:** BCK-0041 (an event is durable in the same commit as the change; committed ⇒ eventually
published, and no event for an uncommitted change) ✓; BCK-0040 (the store only persists; the relay — an
adapter — publishes) ✓.

*Rejected:* dual-write (write the aggregate, then publish directly to the channel) — reopens the exact
lost-event / ghost-event hole BCK-0041 exists to close (crash between commit and publish → event lost).

### D3 — One Postgres server; database-per-context + a dedicated `bus` database (EB-Q2/Q3)

One Postgres **server** for now (operational convenience: one embedded-postgres in tests, one thing to run),
but **one database per context** (each owns its aggregates + outbox + inbox/dedup) **plus a dedicated `bus`
database** that is the platform event log. Relay: read own-DB outbox → append to the `bus` database. Consumer:
read the `bus` database → apply in a transaction in its **own** database. Splitting to real services later =
move a database to its own server (a connection-string change) and/or swap the `bus` database for Kafka (the
D1 adapter swap) — **no domain/app/business-adapter changes.**

This makes split-stability **structural, not disciplinary**: a Postgres database is a hard boundary (no
cross-database joins, no cross-database transactions, no dblink/FDW in use), so a consumer physically *cannot*
join the bus to another context's aggregates or read another context's tables. The shared-database
anti-pattern CON-0012 rejects becomes impossible rather than merely discouraged.

**ADR consistency:** CON-0012 (rejects shared database — the database boundary enforces it) ✓;
CON-0001/CON-0011 (single ownership per context) ✓; BCK-0049 (inbox/dedup in the consumer's own database → an
exactly-once *effect* / exactly-once **application** on top of an at-least-once transport, applied atomically
with the business change) ✓.

*Rejected:* shared schemas in one database (passes split-stability only by discipline; the engine won't stop a
cross-context join or transaction, so drift is a linter away); consumers polling a producer's outbox directly
(reaches into producer persistence — violates the headline invariant, and breaks the moment DBs are split).

### D4 — Outbox and Event Log are two tables in two databases, bridged by the relay (EB-Q, raised as "one table vs two")

Whether a durable record is one table or "the same record viewed differently" is normally an implementation
optimization — but **locking D1–D3 removes the degree of freedom.** The "one table" shape
(`Aggregate Tx → Event Log` directly) needs the Event Log written *inside the aggregate's transaction*, i.e.
in the **producer's** database — which either makes the channel producer-owned (breaking the platform-owned
invariant and forcing consumers to read the producer's DB) or, if kept platform-owned, drops the outbox and
reopens the lost-event hole (BCK-0041). Forced from three directions at once, the shape is: producer
`<ctx>_outbox` (own DB, atomic with the aggregate) → relay → `bus.event_log` (platform DB, the channel).

Symmetry that proves nothing here is throwaway: in the **Kafka era** the `bus.event_log` table disappears and
the **Kafka topic** becomes the log, but the **producer outbox stays**. "Outbox + separate channel" is the
shape in *both* eras; the `bus.event_log` table is simply the Postgres stand-in for a topic.

**ADR consistency:** BCK-0041 ✓; the headline platform-owned-channel invariant ✓.

*Rejected:* the single "one table" collapse (`Aggregate Tx → Event Log`) — only viable in the single
shared-database world rejected in D3; under D1–D3 it necessarily violates either platform-ownership or
BCK-0041.

### D5 — Exactly-once application via a consumer-owned inbox; the cursor is a read optimization (EB-Q4)

The transport contract is **at-least-once** (BCK-0049 rejects exactly-once *delivery* as an infrastructure
guarantee). Correctness is the **consumer's** responsibility and is stated precisely as **exactly-once
application (exactly-once effect) on top of an at-least-once transport** — never "exactly-once delivery." The
mechanism: each consumer's **own** database holds a durable **inbox** (`processed_events`, keyed by
envelope-id); in **one transaction** it records the envelope-id (primary-key conflict ⇒ already applied ⇒
skip) **and** applies the business change via `Consumer.Handle` → coordinator. Because both live in the
consumer's own database (D3), they commit atomically, so a redelivered envelope is a harmless no-op. This is
transport-independent — it holds under PostgreSQL polling, Kafka, NATS, or any future transport.

A per-consumer **cursor/offset** over `bus.event_log` is a **PostgreSQL-era read optimization only** (skip
already-read rows); it carries **no correctness** and is replaced by the broker's own offset under Kafka.
Correctness never depends on the cursor — lose it, rescan from zero, and the inbox makes every re-read a
no-op. Three distinct responsibilities:

| Concern | Owner | Survives Kafka? |
| --- | --- | --- |
| Message transport | Event Bus / Broker | ✅ |
| Read position | Cursor / Broker offset | ❌ (implementation detail) |
| Correctness (exactly-once **application**) | Consumer (`processed_events` inbox) | ✅ |

**ADR consistency:** BCK-0049 (idempotent consumers; the guarantee is exactly-once *application*, not
delivery) ✓; BCK-0046 / DOM-0033 (the envelope-id is the stable dedup key on a completed-fact contract) ✓.

*Rejected:* cursor-only (atomic apply-and-advance without a dedup table) — correct only while a single reader
owns and never rewinds the offset, and it does **not** survive a transport where the broker owns the offset
(a Kafka consumer-group rebalance would re-apply); deferring the inbox to "when Kafka arrives" means
retrofitting correctness under load.

**Refinement — read/write phase separation (D5 ↔ D7).** "In one transaction … records the envelope-id **and**
applies the business change" means the **claim and the *writes* are atomic** — it does **not** mean external
*reads* run inside that transaction. A consumer whose application needs slow external I/O (Knowledge's
correlation issues a per-component feed query; a keyless NVD call can block for minutes) MUST perform that I/O
in a **transaction-free read phase** *before* opening the inbox transaction, and hold only the writes under it.
Reason, and why this is a D7 property not a D5 nicety: a write transaction left open across external calls
holds an assigned XID, which pins the **cluster-wide** `pg_snapshot_xmin` horizon (XIDs are cluster-global);
D7's gap-free watermark `insert_xid8 < pg_snapshot_xmin(pg_current_snapshot())` then cannot advance past any
event newer than that transaction, starving **every** reader on **every** stream — a consumer's own long apply
silently halts the whole bus. Realized by the optional `Preparer` seam on the consumer inbox: `Prepare` runs
the reads and returns an apply closure the inbox runs inside the claimed transaction. Handlers with no external
reads are unaffected and still apply inside the transaction.

### D6 — Per-subject ordering only; no global or cross-context order (EB-Q5)

The platform guarantees **ordered delivery for events belonging to the same aggregate instance** (identified
by `Envelope.Subject`). **No ordering guarantee exists across different aggregate instances or bounded
contexts.** Consumers must **never** rely on global ordering. Duplicate delivery remains possible and is
handled independently by D5's exactly-once **application**.

Realization: PostgreSQL era — a single monotonic `bus.event_log` sequence read in order yields per-subject
order for free (a subset of a totally-ordered stream stays ordered within any subject), so **one cursor
suffices**. Kafka era — partition by `Envelope.Subject`; per-partition offsets preserve per-subject order.
The *guarantee* is stable; only the *mechanism* (single cursor / per-partition offset) is transport-specific
(consistent with D5).

Conditions that make the guarantee real, not nominal:

- **Producer responsibility.** The publishing context must stamp `Envelope.Subject` = the aggregate instance
  whose relative event order is causally significant. Verified for the known flows: all Knowledge→Governance
  events (`ComponentMatched`, `FaultlineEnriched`, `FaultlineSuperseded`) carry the Faultline id, so
  `Subject = FaultlineID` orders them correctly; Governance→Communication keys on the Finding/Position. The
  ordering grain is the **producer's aggregate** (the Faultline), not the consumer's (the Finding) — `Enriched`
  is *about the Faultline*, so it must order ahead of every `ComponentMatched` of that Faultline.
- **No cross-context ordering is safe because the pipeline is a linear DAG** (Evidence → Knowledge →
  Governance → Communication; each consumer reacts to exactly one upstream context). A future fan-in consumer
  that merges two upstreams with a causal dependency uses a **saga keyed on `Envelope.CorrelationID`**, never
  an ordering promise.
- **Parallelism.** M5 runs a single drain loop per consumer, so the guarantee holds trivially. Scaling a
  consumer to multiple workers later must partition by `Subject` (exactly what Kafka does natively).

**ADR consistency:** CON-0012 (autonomy; per-aggregate completed-fact ordering) ✓; BCK-0049 (ordering is the
*causal* safety net, the inbox the *duplicate* safety net — orthogonal) ✓; realizes the Knowledge
order-independent-reconciliation invariant (a commutative consumer treats ordering as a non-issue).

*Rejected:* global total order (PostgreSQL gives it free, but Kafka cannot preserve it across partitions →
split-unstable to depend on it); no ordering at all (forces every consumer to be commutative across lifecycle
transitions — heavier and error-prone, even though Knowledge's reconciliation already is).

### D7 — Subscribe to a stream; dispatch via an interest set; drain is gap-free by observable contract (EB-Q6)

A consumer **subscribes to a stream**, not to event types. Three concerns are kept **separate**:

- **Stream** — the unit of **routing** *and* **ordering**. D6's per-subject order is a property *of the
  stream*. Today there is **one stream per producing bounded context** (Governance ← the Knowledge stream;
  Communication ← the Governance stream), but *stream* is the stable abstraction: the current context-grained
  binding can evolve without redefining subscription.
- **Interest set** — the event types a consumer **dispatches** on within its subscribed stream; types outside
  it are ignored (the existing `Handle` ignore-unknown behaviour, now named). Pure dispatch — it never affects
  routing or ordering.
- **Cursor** — one per (consumer, subscribed stream); the read-position optimization from D5.

Keeping routing/ordering (the stream) apart from dispatch (the interest set) is precisely why per-type
subscription was rejected: it would make the interest set double as the routing key and shatter D6's
cross-type per-subject order. Narrowing an interest set can therefore never break ordering.

**Gap-freedom is stated as an observable property, not an algorithm.** The drain loop MUST consume its stream
**without skipping** any event that will become visible (no lost events from the concurrent-append /
commit-visibility gap). D5's inbox guards *duplicates*, not *gaps*, so gap-freedom is a distinct required
property of the read side. The **mechanism** (e.g. a commit-order / transaction-id watermark, or the broker
providing it natively under Kafka) is deliberately left to implementation and may change without touching
this contract.

**ADR consistency:** CON-0012 (the stream is the collaboration channel; the interest set preserves consumer
autonomy) ✓; BCK-0049 (gap-freedom on the read side + idempotent application together) ✓; realizes D6 (the
stream is the ordering domain).

*Rejected:* per-event-type subscription (makes dispatch the routing key → breaks D6); reading the entire
global log and discarding (scans every context's rows; the stream is the Kafka-faithful "topic"); writing a
specific gap-avoidance algorithm into the EDR (over-specifies — the observable "no gaps" property is the
durable contract).

### D8 — Failures isolate to the smallest consistency boundary; staged delivery (EB-Q7)

**Principle:** failures are isolated to the **smallest possible consistency boundary** — for an ordered
stream that is the **aggregate instance** (`Subject`), because that is the unit within which ordering must
hold. Concretely:

- **Transient failures** (bus unreachable, DB blip, timeout) are **retried indefinitely with backoff** — the
  event is durable in the outbox/log, so there is no loss and no ceremony.
- **Permanent failures** (poison: a recognized event whose application fails every time) are **surfaced, never
  silently discarded**, and **block further processing only for the affected aggregate instance** until
  resolved. **Unrelated aggregate instances continue to make progress.** Silent-skip is forbidden (it is a
  lost event under D6).
- **Replay reuses the original envelope** (same envelope-id), so D5's exactly-once **application** remains
  valid through replay — replay is redelivery, not a new event.

**Staged delivery (contract stable, implementation matures):**

| Layer | Commitment |
| --- | --- |
| **Architectural target** | subject-level isolation (blast radius = one `Subject`) |
| **M5 implementation** | stream-level halt with loud alerting (single drain loop, low volume) |
| **Migration path** | replace the single drain loop with a **subject-aware scheduler** — **no changes to event contracts, D5, D6, or D7** |

**ADR consistency:** BCK-0049 (idempotent + bounded-retry; replay stays idempotent via the envelope-id) ✓;
BCK-0041 (durability underwrites indefinite transient retry) ✓; D6 (never silent-skip — ordering/no-loss
preserved) ✓.

*Rejected:* dead-letter-and-advance (applies later events for the subject without the failed one — violates
D6); silent-skip (lost event); making whole-stream halt the *architectural target* rather than a first
implementation (paints out subject-level isolation).

### D9 — Full envelope threaded end-to-end; integration contract via `schema_ref`, not the raw domain struct (EB-Q8)

**Part 1 — Envelope threading (required).** The full kernel `Envelope` (id, type, occurred-at,
source_context, subject, schema_ref, correlation_id, payload) is the unit **end-to-end**: the outbox stores
it, the relay copies it to `bus.event_log`, the reader hands it to `Consumer.Handle`. This is not optional —
D5 dedups on **id**, D6 orders by **subject**, D7 routes by **source_context**, sagas key on
**correlation_id**. Knowledge's `FaultlineID` generalizes to `Subject`; `source_context` / `schema_ref` /
`correlation_id` are added. This is M5's largest concrete change to the existing seams.

**Part 2 — Integration contract (BCK-0046).** What crosses the boundary is a **producer-owned integration
event** = envelope + a payload that is a **stable, versioned contract identified by `schema_ref`**, decoupled
from the internal domain struct. The domain→integration mapping lives in the **producer's outbound adapter**
(the outbound mirror of the inbound ACL). Staged per the governing principle:

- **Architectural target:** explicit integration DTOs + per-type JSON-schema validation, mapping owned by the
  producer.
- **M5 implementation:** thread the envelope; **freeze the current payload shapes as integration-contract
  v1**, each pinned to a `schema_ref` and **guarded by a contract test** (the produced payload validates
  against a checked-in schema) — so a domain refactor that reshapes the wire **fails the test** instead of
  silently breaking a consumer (the exact BCK-0046 failure mode: e.g. renaming `FaultlineEnriched.Severity`).
- **Migration path:** introduce explicit DTOs / an outbound mapping layer **without changing `schema_ref` v1
  or the transport**.

**ADR consistency:** BCK-0046 (domain vs integration events; the producer owns the mapping; `schema_ref` is
the versioning hook) ✓; realizes KERNEL-D4 (the kernel envelope is now actually threaded; its machinery lives
here) ✓; D5/D6/D7 (their keys are envelope fields) ✓; BCK-0040 (mapping is an adapter concern, not
domain/app) ✓.

*Rejected:* leaving the raw domain struct as the **unguarded** wire contract (a domain refactor silently
breaks consumers — the BCK-0046 failure); putting the domain→integration mapping in domain/app (the domain
emits domain events; mapping to the stable contract is an adapter responsibility).

### D10 — Platform owns transport infrastructure; contexts own messaging semantics; per-context binaries (EB-Q9)

- **Platform (`internal/platform/eventbus`) owns the transport infrastructure:** event log (`bus` store +
  migrations), publisher, reader (drain engine), **scheduling, retry policies, and transport mechanics**. It
  depends **only** on the kernel (`Envelope` and supporting abstractions) and infrastructure drivers — never a
  bounded context. Depguard-restricted to adapters + `cmd`, exactly like `internal/platform/observability`.
- **Each bounded context owns its messaging semantics:** outbox, relay, consumer handler (`Handle`), inbox
  (`processed_events`), and subscription declarations (stream + interest set).
- **Composition roots (`cmd/*`) assemble the pipeline** by wiring relays, readers, and handlers. **Every
  deployable bounded context has its own binary** — M5 adds the missing **`cmd/knowledge`**.
- **Production deployment remains one binary per bounded context.** Development and end-to-end testing MAY use
  a **composed in-process binary** wiring all contexts against a shared PostgreSQL instance — a **developer
  convenience, not a deployment model** (consistent with D3: process count is a deployment detail).

This keeps the platform **completely business-agnostic** and lets the implementation evolve (subject-aware
scheduling, Kafka) without changing the architectural contracts (the governing principle).

**ADR consistency:** CON-0014 (business-capability separation — transport is not a business capability) ✓;
CON-0012 (the platform is the collaboration channel, owned by neither business context) ✓; the observability
depguard precedent ✓.

*Rejected:* a shared all-in-one **production** binary (blurs the per-context deployable boundary; in-process
composition is dev/test-only); pushing scheduling/retry into the contexts (duplicates transport mechanics and
couples business code to transport concerns).

### D11 — Definition of Done: async-only SBOM → OpenVEX, proven black-box + platform + architectural (EB-Q10)

**Definition of Done.** M5 is complete when an SBOM can be **ingested** and a **publishable OpenVEX artifact
is eventually produced** using **only asynchronous event-based communication between bounded contexts**, with
**no synchronous cross-context orchestration**. Read-only read-API queries (e.g. Knowledge reading Evidence's
inventory during correlation) remain **permitted** — they are data reads, not workflow causation; the
prohibition is on a context synchronously *driving/commanding* another. All state-changing collaboration is
event-driven.

Proven in three layers, aligned to the architecture rather than the internal implementation:

- **One black-box pipeline E2E (SBOM → OpenVEX).** Drives the public input (SBOM upload) and observes the
  public output (the OpenVEX artifact), never internal state; asserts the artifact **eventually** appears with
  the expected stance within a timeout, via the in-process composition (D10) over one embedded PostgreSQL
  server. Home: `tests/e2e/pipeline_e2e_test.go` (`//go:build e2e`, `make e2e-pipeline`) — top-level, so it
  composes all contexts without tripping go-cleanarch's per-context scan.
- **Three focused platform tests.** D5 (redeliver → exactly-once **application**: no duplicate
  Finding/Position/Publication); D6 (`FaultlineEnriched` before `FaultlineSuperseded` for one `Subject` is
  honored); D8 (a poison event halts its stream **loudly** with an alert, never silently dropped).
- **Architectural assertions.** Eventual consistency (the pipeline completes only after the async drains run)
  and the **absence of synchronous cross-context orchestration** — enforced *statically* by the existing
  arch-test/depguard: a context may import only another context's read-API **client seam** + the platform
  eventbus, never its `app`/`domain`, so synchronous orchestration is structurally impossible.

**ADR consistency:** CON-0012 (event-driven collaboration is the mechanism; read-only read-APIs permitted) ✓;
D5/D6/D8 (the focused tests prove the reliability contracts) ✓; the architecture test enforces the boundary ✓.

*Rejected:* a white-box e2e reaching into internal state (couples the test to implementation); asserting "no
cross-context calls **at all**" (would wrongly forbid the sanctioned read-only read-API queries).

---

## Grilling complete

All branches resolved (**D1–D11**). This EDR is the source of truth for **M5 — Event Infrastructure**. The
one cross-cutting hand-off it consumed is `EDR-KERNEL-01` D4 (the "M5-seed"): the kernel provides the
behavior-free `Envelope`; M5 owns the outbox runner + relay + platform channel + drain engine.

**Ubiquitous language introduced / sharpened** (candidates for the architecture book's ubiquitous-language
chapter when M5 lands): **Stream** (routing + ordering unit; one per producing context today), **Interest
set** (dispatch filter), **Inbox** (`processed_events`, the exactly-once-application guard), **Event Log**
(the platform channel; Postgres stand-in for a topic), **exactly-once application** vs **at-least-once
transport**.

## Traceability → issues

Suggested delivery: an OpenSpec change `openspec/changes/phase3-event-infrastructure/` (a `phase3-*` change —
proposal/design/tasks with this EDR as source of truth, **no `specs/` deltas**).

| # | Issue | Realizes |
| --- | --- | --- |
| EB-01 | `internal/platform/eventbus` scaffold + `bus` database & migrations (`event_log`: seq, envelope_id, source_context, subject, type, occurred_at, correlation_id, schema_ref, payload); depguard (adapters + `cmd` only); arch-test: eventbus imports only kernel + drivers | D3 · D4 · D10 |
| EB-02 | Thread the full kernel `Envelope` end-to-end: generalize each context's outbox row (Subject, source_context, schema_ref, correlation_id); evolve `Consumer.Handle` to carry the `Envelope` | D9 · KERNEL-D4 |
| EB-03 | Integration-contract **v1 freeze**: a `schema_ref`'d JSON schema per published event type + a contract test guarding the produced payload | D9 · BCK-0046 |
| EB-04 | Platform `Publisher` (append envelope → `bus.event_log`); swap each context's `logPublisher` stand-in for it | D1 · D2 · D4 |
| EB-05 | Platform stream `Reader` / drain engine: gap-free watermark read + per-consumer cursor; D8 stream-halt-with-alert policy | D5 · D6 · D7 · D8 |
| EB-06 | Consumer **inbox** (`processed_events`) in each consuming context's DB; apply-in-one-transaction (record-processed + `Handle`) → exactly-once application | D5 |
| EB-07 | Per-context **subscription** declarations (stream + interest set): Knowledge ← evidence, Governance ← knowledge, Communication ← governance | D7 |
| EB-08 | `cmd/knowledge` (missing composition root); wire relays + readers in each `cmd/*`; in-process composed pipeline runner for dev/e2e | D10 |
| EB-09 | Black-box pipeline e2e `tests/e2e/pipeline_e2e_test.go` (SBOM → OpenVEX) + `make e2e-pipeline` | D11 |
| EB-10 | Focused platform tests (D5 idempotency, D6 ordering, D8 poison-halt) + architectural assertion (no synchronous cross-context orchestration) | D11 · D5 · D6 · D8 |
| EB-11 | Docs: `PHASE3-STATUS` (M5 done), `BACKLOG` (mark M5), `STACK` (M5 realized), `openspec/STATUS`; ubiquitous-language additions | — |
