# Tasks — phase3-event-infrastructure (Event Infrastructure / M5 — the platform event bus)

> **Scope: M5 only** — the platform-owned channel between the existing per-context outboxes and inbound
> consumers, plus the wiring that carries one SBOM through all four contexts as events to a published OpenVEX.
> All decisions trace to `docs/engineering/decisions/EDR-EVENTBUS-01.md` **(D1–D11)**; task IDs map to its
> issue table **(EB-01…EB-11)**. Each group ends with the six Themis gates (`make check`), extended to the new
> packages. M5 adds **no external broker and no new third-party dependency** — PostgreSQL only. Governing
> principle: *freeze contracts early; evolve implementations later* — where a decision is staged, build the
> **M5 cut** and leave the target as a documented seam, never a behaviorless stub.

## 1. Platform scaffold + `bus` database (EB-01 · D3/D4/D10)

- [ ] 1.1 Create `internal/platform/eventbus` with a `doc.go` stating it owns transport infrastructure and
  depends **only** on the kernel (`Envelope`) + drivers — never a bounded context.
- [ ] 1.2 `bus` database + migrations under `internal/platform/eventbus/migrations/`: `event_log` (seq
  `bigserial` PK, envelope_id unique, source_context, subject, type, occurred_at, correlation_id, schema_ref,
  payload `jsonb`) with indexes for stream filter (source_context) + ordering (seq) + dedup (envelope_id);
  up/down reversibility.
- [ ] 1.3 Extend depguard so `internal/platform/eventbus` is importable only by adapters + `cmd` (mirror the
  `observability` rule); arch-test asserting eventbus imports only kernel + drivers, no context.
- [ ] 1.4 Register the package in the coverage tiers (`scripts/check-coverage.sh` + Makefile `COVERAGE_PKGS`).
- [ ] 1.5 Gate: build · lint · clean-arch · arch-test · coverage · deadcode green.

## 2. Thread the full kernel `Envelope` end-to-end (EB-02 · D9 · KERNEL-D4)

- [ ] 2.1 Generalize each context's outbox row to carry the full `Envelope` (add `source_context`,
  `schema_ref`, `correlation_id`; generalize the context-specific subject column — e.g. Knowledge's
  `faultline_id` — to `subject`); migrations with up/down.
- [ ] 2.2 Evolve the outbound path so the relay reads an `Envelope` (not the reduced `OutboxNote`), and the
  inbound `Consumer.Handle` carries the `Envelope` (type + payload accessible from it); keep the ACL decode
  logic and the ignore-unknown behaviour unchanged.
- [ ] 2.3 Tests: envelope round-trips outbox → (relay) → reader → `Handle` with all fields intact; existing
  per-context consumer tests updated to the envelope-carrying signature.
- [ ] 2.4 Gate: six Themis gates green.

## 3. Integration-contract v1 + schema guard (EB-03 · D9 · BCK-0046)

- [ ] 3.1 For each published event type, add a checked-in JSON schema and pin the producer's `Envelope.SchemaRef`
  to it (contract **v1** = the current payload shape frozen). Mapping stays in the producer's outbound adapter.
- [ ] 3.2 **Contract test** per event type: the produced payload validates against its schema (jsonschema/v6),
  so a domain-struct refactor that reshapes the wire fails the test rather than silently breaking a consumer.
- [ ] 3.3 Note (design record, not code): explicit integration DTOs are the deferred maturation — v1 freeze +
  guard is the M5 cut.
- [ ] 3.4 Gate: six Themis gates green.

## 4. Platform `Publisher`: outbox → `bus.event_log` (EB-04 · D1/D2/D4)

- [ ] 4.1 `eventbus.Publisher` appends an `Envelope` to `bus.event_log` (at-least-once; the outbox row stays
  until the append is confirmed, then the relay marks it sent — BCK-0041 durability preserved).
- [ ] 4.2 Swap each context's `logPublisher` stand-in for the real `Publisher` in wiring/`cmd`.
- [ ] 4.3 Tests: publish appends exactly one log row per outbox note; relay marks sent on success / bumps
  attempts on failure (existing relay behaviour, now against the real sink).
- [ ] 4.4 Gate: six Themis gates green.

## 5. Stream `Reader` / drain engine: gap-free + D8 policy (EB-05 · D5/D6/D7/D8)

- [ ] 5.1 `eventbus.Reader` (the drain engine): read a subscribed **stream** (filter by source_context) with a
  per-consumer **cursor**, in `seq` order (per-subject order for free — D6), calling a generic
  `Handler(ctx, Envelope) error`.
- [ ] 5.2 **Gap-free** advance (observable contract): do not skip an event that will become visible — apply a
  commit-order / txid watermark so a late-committing lower `seq` is not stepped over (the inbox guards
  duplicates, not gaps). Mechanism is internal to the engine and may change.
- [ ] 5.3 **D8 policy (M5 cut):** transient failure → retry with backoff; poison (bounded attempts on a
  recognized event) → **halt the stream with a loud alert** (OTel + console), never silent-skip; the
  subject-aware scheduler is the documented migration target, not built here.
- [ ] 5.4 Tests: gap scenario (concurrent appends) never loses an event; poison halts the stream + alerts;
  transient error retries.
- [ ] 5.5 Gate: six Themis gates green.

## 6. Consumer inbox: exactly-once application (EB-06 · D5)

- [ ] 6.1 Per consuming context: a `processed_events` inbox table in the **context's own** database; migration
  up/down.
- [ ] 6.2 The reader's apply path runs in **one transaction in the consumer's own DB**: insert the envelope-id
  (primary-key conflict ⇒ already applied ⇒ skip) **and** call `Handle` — exactly-once **application** on an
  at-least-once transport.
- [ ] 6.3 Tests: redelivery of the same envelope-id applies once (no duplicate Finding/Position/Publication);
  a distinct envelope applies normally.
- [ ] 6.4 Gate: six Themis gates green.

## 7. Subscriptions: stream + interest set (EB-07 · D7)

- [ ] 7.1 Per-context subscription declarations: the **stream** it consumes (Knowledge ← evidence, Governance
  ← knowledge, Communication ← governance) + its **interest set** of event types (the existing `Handle`
  ignore-unknown, now explicit).
- [ ] 7.2 Wire each subscription to a platform `Reader` in the context's adapters (business-agnostic engine,
  context-supplied `Handle` + DB pool + inbox).
- [ ] 7.3 Tests: a consumer receives only its stream's events; unknown/out-of-interest types are ignored;
  narrowing the interest set never affects ordering.
- [ ] 7.4 Gate: six Themis gates green.

## 8. Composition: `cmd/knowledge` + wiring + in-process runner (EB-08 · D10)

- [ ] 8.1 Add the missing **`cmd/knowledge`** composition root (own binary, own DB, runs its relay + a reader
  on the evidence stream).
- [ ] 8.2 Wire each `cmd/*` to run its relay + reader(s): `evidence` (relay only), `governance` (relay +
  knowledge reader), `communication` (relay + governance reader).
- [ ] 8.3 An **in-process composed pipeline runner** (dev/e2e only) wiring all contexts against one PostgreSQL
  server (N context DBs + `bus` DB) — a developer convenience, not a deployment model; production stays
  per-context binaries.
- [ ] 8.4 Gate: six Themis gates green.

## 9. Pipeline e2e + focused platform tests + arch assertion (EB-09, EB-10 · D11 · D5/D6/D8)

- [ ] 9.1 **Black-box pipeline e2e** `tests/e2e/pipeline_e2e_test.go` (`//go:build e2e`, `make e2e-pipeline`):
  register a Release + upload an SBOM to Evidence → assert a published **OpenVEX** artifact eventually appears
  with the expected stance under a timeout, driven **only** over the `bus` via the in-process runner, no
  internal-state peeking.
- [ ] 9.2 **Three focused platform tests:** D5 (redeliver → exactly-once application), D6 (`FaultlineEnriched`
  before `FaultlineSuperseded` for one `Subject` honored), D8 (poison halts its stream loudly, never dropped).
- [ ] 9.3 **Architectural assertion:** the existing arch-test/depguard confirm no context imports another's
  `app`/`domain` (only the read-API client seam + eventbus) — record it as the "no synchronous cross-context
  orchestration" guarantee (extend the arch test with an explicit case/comment if needed).
- [ ] 9.4 Gate: six Themis gates green; `make e2e-pipeline` green.

## 10. Docs + status (EB-11)

- [ ] 10.1 Update `docs/engineering/PHASE3-STATUS.md` (M5 done; the wired SBOM → published-VEX e2e now green),
  `docs/BACKLOG.md` (mark the M5 line; note D8 subject-aware scheduler + D9 explicit DTOs
  as the remaining maturations), `docs/engineering/STACK.md` (M5 realized), and `openspec/STATUS.md`.
- [ ] 10.2 Add the M5 ubiquitous language (Stream, Interest set, Inbox / `processed_events`, Event Log,
  exactly-once application vs at-least-once transport) to the architecture book's ubiquitous-language chapter.
- [ ] 10.3 Update `TESTING.md` with the `make e2e-pipeline` how-to.
- [ ] 10.4 **Wire `make e2e-pipeline` into CI.** The `ci/add-workflows` change adds
  `.github/workflows/{pr,main}.yml` (`main.yml` runs `make check` + `make e2e-evidence`; `pr.yml` runs
  `make check`). Once `make e2e-pipeline` exists (9.1) and that CI change has merged, add an `e2e-pipeline`
  step to `main.yml` (post-merge), mirroring the `e2e-evidence` step — and to `pr.yml` if pre-merge pipeline
  proof is wanted. Kept **out of `make check`** deliberately (e2e is slow; consistent with `e2e-evidence`).
  Tracked in `docs/BACKLOG.md` §E.
- [ ] 10.5 Gate: six Themis gates green; `markdownlint-cli2` clean.
