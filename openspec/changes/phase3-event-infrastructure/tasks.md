# Tasks — phase3-event-infrastructure (Event Infrastructure / M5 — the platform event bus)

> **Scope: M5 only** — the platform-owned channel between the existing per-context outboxes and inbound
> consumers, plus the wiring that carries one SBOM through all four contexts as events to a published OpenVEX.
> All decisions trace to `docs/engineering/decisions/EDR-EVENTBUS-01.md` **(D1–D11)**; task IDs map to its
> issue table **(EB-01…EB-11)**. Each group ends with the six Themis gates (`make check`), extended to the new
> packages. M5 adds **no external broker and no new third-party dependency** — PostgreSQL only. Governing
> principle: *freeze contracts early; evolve implementations later* — where a decision is staged, build the
> **M5 cut** and leave the target as a documented seam, never a behaviorless stub.

## 1. Platform scaffold + `bus` database (EB-01 · D3/D4/D10)

- [x] 1.1 Create `internal/platform/eventbus` with a `doc.go` stating it owns transport infrastructure and
  depends **only** on the kernel (`Envelope`) + drivers — never a bounded context.
- [x] 1.2 `bus` database + migrations under `internal/platform/eventbus/migrations/`: `event_log` (seq
  `bigserial` PK, envelope_id unique, source_context, subject, type, occurred_at, correlation_id, schema_ref,
  payload `jsonb`) with indexes for stream filter (source_context) + ordering (seq) + dedup (envelope_id);
  up/down reversibility.
- [x] 1.3 Extend depguard so `internal/platform/eventbus` is importable only by adapters + `cmd` (mirror the
  `observability` rule); arch-test asserting eventbus imports only kernel + drivers, no context.
- [x] 1.4 Register the package in the coverage tiers (`scripts/check-coverage.sh` + Makefile `COVERAGE_PKGS`).
- [x] 1.5 Gate: build · lint · clean-arch · arch-test · coverage · deadcode green.

## 2. Thread the full kernel `Envelope` end-to-end (EB-02 · D9 · KERNEL-D4)

- [x] 2.1 Generalize each context's outbox row to carry the full `Envelope` (add `source_context`,
  `schema_ref`, `correlation_id`; generalize the context-specific subject column — e.g. Knowledge's
  `faultline_id` — to `subject`); migrations with up/down. Done for all four producers: evidence, knowledge,
  governance (`000002_governance_envelope`), communication (`000002_communication_envelope`).
- [x] 2.2 Evolve the outbound path so the relay reads an `Envelope` (not the reduced `OutboxNote`), and the
  inbound `Consumer.Handle` carries the `Envelope` (type + payload accessible from it); keep the ACL decode
  logic and the ignore-unknown behaviour unchanged. Both inbound consumers (governance ← knowledge,
  communication ← governance) now take `event.Envelope`; the HTTP intake seam decodes the full envelope JSON.
- [x] 2.3 Tests: envelope round-trips outbox → (relay) → reader → `Handle` with all fields intact; existing
  per-context consumer tests updated to the envelope-carrying signature. (Reader lands in Group 5; the M5-cut
  round-trip is outbox → relay → Publisher, asserted field-for-field in the governance store test.)
- [x] 2.4 Gate: six Themis gates green.

## 3. Integration-contract v1 + schema guard (EB-03 · D9 · BCK-0046)

- [x] 3.1 For each published event type, add a checked-in JSON schema and pin the producer's `Envelope.SchemaRef`
  to it (contract **v1** = the current payload shape frozen). Mapping stays in the producer's outbound adapter.
  _All 18 published types frozen: Evidence 1, Knowledge 5, Governance 9, Communication 3. Each store owns a
  `schemaRefByEventType` map + `schemaRefFor` helper stamping `schema_ref`; schemas under
  `internal/<ctx>/adapters/store/schemas/`._
- [x] 3.2 **Contract test** per event type: the produced payload validates against its schema (jsonschema/v6),
  so a domain-struct refactor that reshapes the wire fails the test rather than silently breaking a consumer.
  _In-package `contract_test.go` per context, table-driven over every event type + a completeness check
  (schema-file count == frozen-type count) + the unmapped-fallback branch._
- [x] 3.3 Note (design record, not code): explicit integration DTOs are the deferred maturation — v1 freeze +
  guard is the M5 cut. _Recorded in design.md D9 "As-built (EB-03)": Evidence has a DTO (snake_case v1);
  Knowledge/Governance/Communication freeze the raw-struct PascalCase shape — that asymmetry is the DTO
  migration surface._
- [x] 3.4 Gate: six Themis gates green.

## 4. Platform `Publisher`: outbox → `bus.event_log` (EB-04 · D1/D2/D4)

- [x] 4.1 `eventbus.Publisher` appends an `Envelope` to `bus.event_log` (at-least-once; the outbox row stays
  until the append is confirmed, then the relay marks it sent — BCK-0041 durability preserved).
  _`internal/platform/eventbus/publisher.go`: INSERT built from the `Col*`/`TableEventLog` constants with
  `ON CONFLICT (envelope_id) DO NOTHING` → idempotent at-most-once append (D5), so the at-least-once relay
  redelivering never duplicates a log row. Thin (no-payload) events store SQL NULL._
- [x] 4.2 Swap each context's `logPublisher` stand-in for the real `Publisher` in wiring/`cmd`.
  _`cmd/{evidence,governance,communication}` gained a `newPublisher` helper + `THEMIS_BUS_DATABASE_DSN`
  (self-documented config): when set it opens a `bus` pool and uses `eventbus.NewPublisher` (optionally
  migrating the bus via `THEMIS_BUS_MIGRATE=1`); when empty it keeps `logPublisher` as a no-bus dev fallback.
  `cmd/knowledge` does not exist yet — its swap lands with the composition root in Group 8._
- [x] 4.3 Tests: publish appends exactly one log row per outbox note; relay marks sent on success / bumps
  attempts on failure (existing relay behaviour, now against the real sink). _Split by the eventbus
  business-agnostic boundary: `publisher_integration_test.go` (embedded Postgres + bus migrations, 100% pkg
  cov) proves one-row-per-envelope, idempotent re-publish, monotonic seq, NULL payload, and error surfacing;
  the relay's mark-sent / attempts-bump stays covered by each context's existing relay integration tests
  (a fake publisher) — the eventbus package imports no context._
- [x] 4.4 Gate: six Themis gates green.

## 5. Stream `Reader` / drain engine: gap-free + D8 policy (EB-05 · D5/D6/D7/D8)

- [x] 5.1 `eventbus.Reader` (the drain engine): read a subscribed **stream** (filter by source_context) with a
  per-consumer **cursor**, in `seq` order (per-subject order for free — D6), calling a generic
  `Handler(ctx, Envelope) error`. _`internal/platform/eventbus/reader.go`: `Handler` interface (a context's
  inbound `Consumer.Handle` satisfies it structurally); cursor is the `stream_cursor` table in the `bus` DB
  (per consumer+stream), advanced **outside** the apply tx — a lost cursor rescans as a no-op (D5)._
- [x] 5.2 **Gap-free** advance (observable contract): do not skip an event that will become visible — apply a
  commit-order / txid watermark so a late-committing lower `seq` is not stepped over (the inbox guards
  duplicates, not gaps). Mechanism is internal to the engine and may change. _Mechanism: `insert_xid8 xid8
  DEFAULT pg_current_xact_id()` (migration 000002) + read predicate `insert_xid8 <
  pg_snapshot_xmin(pg_current_snapshot())`. The Publisher writes one row per tx so xid order == seq order;
  permanent seq gaps (rollback / `ON CONFLICT`-burned nextval) are simply absent and skipped without waiting.
  Proven by `TestReader_GapFree`: a higher seq committed while a lower seq is in-flight is held back until the
  earlier tx settles, then both deliver in seq order._
- [x] 5.3 **D8 policy (M5 cut):** transient failure → retry with backoff; poison (bounded attempts on a
  recognized event) → **halt the stream with a loud alert** (OTel + console), never silent-skip; the
  subject-aware scheduler is the documented migration target, not built here. _`deliver` retries with capped
  exponential backoff up to `MaxAttempts`; exhaustion → `logger.Error("… HALTED …")` + `halted=true` +
  `ErrStreamHalted` (cursor not advanced, later Drains no-op). A ctx cancel mid-backoff returns `ctx.Err()`,
  not a halt (no false poison)._
- [x] 5.4 Tests: gap scenario (concurrent appends) never loses an event; poison halts the stream + alerts;
  transient error retries. _`reader_integration_test.go`: seq-order drain + durable cursor, gap-free,
  poison-halt+alert (zap observer asserts the alert)+no-advance+subsequent-halt, transient retry-then-succeed,
  ctx-cancel-not-poison; plus `reader_internal_test.go` for backoff/sleep/defaults and `TestMigration_DownUp`.
  eventbus pkg 93.1%._
- [x] 5.5 Gate: six Themis gates green.

## 6. Consumer inbox: exactly-once application (EB-06 · D5)

- [x] 6.1 Per consuming context: a `processed_events` inbox table in the **context's own** database; migration
  up/down. _Added to **Governance** (`000003_governance_inbox`) and **Communication** (`000003_communication_inbox`).
  **Knowledge deferred to Group 8**: it has no inbound bus-consumer adapter yet (its `OnEvidenceRegistered`
  coordinator exists but nothing decodes an Envelope into it — that lands with `cmd/knowledge` wiring), and its
  applies are idempotent by design (RecordMatch is a no-op re-scan; reconciliation is order-independent), so no
  duplicate risk in the interim. Tracked in docs/BACKLOG.md._
- [x] 6.2 The reader's apply path runs in **one transaction in the consumer's own DB**: insert the envelope-id
  (primary-key conflict ⇒ already applied ⇒ skip) **and** call `Handle` — exactly-once **application** on an
  at-least-once transport. _Mechanism: a **ctx-scoped unit of work** — `store.InboxConsumer` (decorates the
  inbound Consumer) begins one tx on the context's own pool, claims the envelope-id (`ON CONFLICT DO NOTHING`),
  stashes the tx in ctx, and runs the inner `Handle`; the write path joins that tx (`beginOrJoin` for
  Governance's multi-statement `Save`, `exec(ctx)` for Communication's single-statement `MarkPublishable`).
  The claim is **event-level**, so a fan-out apply (one enrichment → many Findings) still commits atomically
  under one dedup key. Reads stay on the pool (inbound applies don't read-their-own-writes within an envelope)._
- [x] 6.3 Tests: redelivery of the same envelope-id applies once (no duplicate Finding/Position/Publication);
  a distinct envelope applies normally. _Governance: a redelivered `FaultlineEnriched` (non-idempotent — raises
  a proposal) adds no second proposal; malformed-payload apply error rolls back the claim (retry-able).
  Communication: an **old** `PositionEstablished` redelivered after a newer `PositionRevised` does not revert
  the worklist (version stays 2/stale) — a deterministic non-idempotent proof._
- [x] 6.4 Gate: six Themis gates green.

## 7. Subscriptions: stream + interest set (EB-07 · D7)

- [x] 7.1 Per-context subscription declarations: the **stream** it consumes (Knowledge ← evidence, Governance
  ← knowledge, Communication ← governance) + its **interest set** of event types (the existing `Handle`
  ignore-unknown, now explicit). _`eventbus.Subscription{Consumer, Stream, Interest}` (business-agnostic —
  opaque strings). Declared in each `inbound` package: `governance` ← knowledge stream {component_matched,
  faultline_enriched, faultline_superseded}; `communication` ← governance stream {position_established,
  position_revised}. **Knowledge deferred to Group 8** with its consumer (same as EB-06)._
- [x] 7.2 Wire each subscription to a platform `Reader` in the context's adapters (business-agnostic engine,
  context-supplied `Handle` + DB pool + inbox). _`Subscription.NewReader(busPool, logger, handler)` binds the
  stream to a `Reader` and wraps the handler in an **interest filter** — out-of-interest events are skipped as
  no-ops *before* the inbox, so `processed_events` records only applied events. Composition (Group 8) calls
  `inbound.Subscription.NewReader(busPool, logger, store.NewInboxConsumer(ctxPool, consumer))`._
- [x] 7.3 Tests: a consumer receives only its stream's events; unknown/out-of-interest types are ignored;
  narrowing the interest set never affects ordering. _eventbus integration `TestSubscription_StreamAndInterestFilter`:
  events on another `source_context` are never delivered (no cursor there); an out-of-interest type is skipped
  (cursor still advances); the two in-interest events reach the handler in seq order despite the interleaved
  skip. Plus `Subscription.InInterest` unit test + a per-context `TestSubscription` asserting the declared set._
- [x] 7.4 Gate: six Themis gates green.

## 8. Composition: `cmd/knowledge` + wiring + in-process runner (EB-08 · D10)

- [x] 8.1 Add the missing **`cmd/knowledge`** composition root (own binary, own DB, runs its relay + a reader
  on the evidence stream). _`cmd/knowledge/main.go` (:8082): Faultline read API + relay + evidence-stream
  reader. Prereq built first — Knowledge's deferred EB-06/07 pieces now exist: `adapters/inbound` (decode
  `EvidenceRegistered` → correlation + Subscription), `processed_events` inbox + `InboxConsumer`, and
  `Save`/`RecordMatch` join the ctx-tx (correlation fans out over SBOM components). Fuller `wiring.Wire`
  assembles the correlation pipeline (Evidence read-API client + OSV discovery + FaultlineService)._
- [x] 8.2 Wire each `cmd/*` to run its relay + reader(s): `evidence` (relay only), `governance` (relay +
  knowledge reader), `communication` (relay + governance reader). _Each cmd now shares an `openBus` helper
  (opens the `bus` pool once for the Publisher + Reader, or nil → logging publisher + reader disabled) and a
  `readerLoop` (poison halt stops the loop loudly). Reader built via `inbound.Subscription.NewReader(busPool,
  logger, store.NewInboxConsumer(ctxPool, consumer))`._
- [x] 8.3 An **in-process composed pipeline runner** (dev/e2e only) wiring all contexts against one PostgreSQL
  server (N context DBs + `bus` DB) — a developer convenience, not a deployment model; production stays
  per-context binaries. _`tests/pipeline` (`//go:build e2e`, `make e2e-pipeline`): one embedded Postgres, a
  database per context + `bus`, all four contexts wired and driven through the real bus by a `pump` that
  cascades relays→readers. `TestPipeline_SBOMToFaultline` pushes an SBOM in and observes a correlated
  Faultline out — end-to-end proof of the whole M5 stack (outbox+relay → Publisher → gap-free Reader +
  interest filter → exactly-once inbox → correlation). Full SBOM→published-VEX assertion is Group 9._
- [x] 8.4 Gate: six Themis gates green.

## 9. Pipeline e2e + focused platform tests + arch assertion (EB-09, EB-10 · D11 · D5/D6/D8)

- [x] 9.1 **Black-box pipeline e2e** (`//go:build e2e`, `make e2e-pipeline`): register a Release + upload an
  SBOM to Evidence → assert a published **OpenVEX** artifact eventually appears with the expected stance,
  driven **only** over the `bus` via the in-process runner, no internal-state peeking. _`tests/pipeline`
  (separate package from `tests/e2e` to avoid a TestMain clash): `TestPipeline_SBOMToPublishedVEX` uploads an
  SBOM, discovers the Finding via Governance's posture read API, governs an **affected** Position (raise +
  accept over the triage API), triggers the OpenVEX publication, and asserts the artifact via Communication's
  read API — the payload (fetched by id) names the CVE. Every observation is over a public HTTP API._
- [x] 9.2 **Three focused platform tests:** D5 (redeliver → exactly-once application), D6 (`FaultlineEnriched`
  before `FaultlineSuperseded` for one `Subject` honored), D8 (poison halts its stream loudly, never dropped).
  _D5: the per-context inbox integration tests (Governance/Communication/Knowledge) prove a redelivered
  envelope applies once. D6: `TestReader_PerSubjectOrderPreserved` (same Subject, enriched-then-superseded
  delivered in order). D8: `TestReader_PoisonHaltsStreamAndAlerts` (bounded retries → halt + loud alert,
  cursor not advanced, no silent skip)._
- [x] 9.3 **Architectural assertion:** the existing arch-test/depguard confirm no context imports another's
  `app`/`domain` (only the read-API client seam + eventbus) — record it as the "no synchronous cross-context
  orchestration" guarantee. _`TestContextFirstArchitecture` case (1) bans all cross-context imports; expanded
  its comment to name the **no synchronous cross-context orchestration** guarantee (collaboration only via
  async bus events + the read-only HTTP client seam), proven live by `tests/pipeline`._
- [x] 9.4 Gate: six Themis gates green; `make e2e-pipeline` green.

## 10. Docs + status (EB-11)

- [x] 10.1 Update `docs/engineering/PHASE3-STATUS.md` (M5 done; the wired SBOM → published-VEX e2e now green),
  `docs/BACKLOG.md` (mark the M5 line; note D8 subject-aware scheduler + D9 explicit DTOs
  as the remaining maturations), `docs/engineering/STACK.md` (M5 realized), and `openspec/STATUS.md`.
  _All four updated to M5 DONE (43/43); the three maturations (Kafka swap, subject-aware scheduler, explicit
  DTOs) are their own LOW backlog items under the M5 entry._
- [x] 10.2 Add the M5 ubiquitous language (Stream, Interest set, Inbox / `processed_events`, Event Log,
  exactly-once application vs at-least-once transport) to the architecture book's ubiquitous-language chapter.
  _New §2.6 "Event Infrastructure Vocabulary (M5)" in Book-II Chapter 2._
- [x] 10.3 Update `TESTING.md` with the `make e2e-pipeline` how-to. _Added under Part A "Composed pipeline
  end-to-end" — the in-process runner, black-box SBOM→OpenVEX, skips without Postgres, post-merge in CI._
- [ ] 10.4 **Wire `make e2e-pipeline` into CI.** The `ci/add-workflows` change adds
  `.github/workflows/{pr,main}.yml` (`main.yml` runs `make check` + `make e2e-evidence`; `pr.yml` runs
  `make check`). Once `make e2e-pipeline` exists (9.1) and that CI change has merged, add an `e2e-pipeline`
  step to `main.yml` (post-merge), mirroring the `e2e-evidence` step — and to `pr.yml` if pre-merge pipeline
  proof is wanted. Kept **out of `make check`** deliberately (e2e is slow; consistent with `e2e-evidence`).
  Tracked in `docs/BACKLOG.md` §E. _Added the `e2e-pipeline` step to `main.yml` (post-merge), mirroring
  `e2e-evidence`._
- [x] 10.5 Gate: six Themis gates green; `markdownlint-cli2` clean.
