# Tasks — phase3-communication (Communication bounded context)

> Scope: the Communication context per `proposal.md` / `design.md`; all decisions trace to
> `docs/engineering/decisions/EDR-COMMUNICATION-01.md` (D1–D12). Each group ends with the six Themis gates
> (`make check`), extended to `internal/communication/`. Task IDs map to the EDR issue table (COMM-01…12).
> Depends on `phase3-governance` (`PositionEstablished` / `PositionRevised` + `GetPosition`).

## 1. Context scaffold + architecture enforcement (COMM-01 · D12)

- [x] 1.1 Create `internal/communication/{domain,app,adapters}` with a `doc.go` per package stating the
  ring.
- [x] 1.2 Extend `go-cleanarch` + depguard; architecture test asserting inward-only + no cross-context
  imports. — `communication` added to `boundedContexts` + `GREENFIELD_CONTEXTS`; `communication-{domain-inner
  [stdlib-only, pure], app-domain-only, no-cross-context}` depguard rules (deny evidence/knowledge/governance/
  intelligence).
- [x] 1.3 Gate: build green; clean-architecture check green. — build + arch-test + go-cleanarch + lint green.

## 2. Domain — Publication, materialization, events (COMM-02, COMM-03, COMM-04 · D1/D3/D5/D8/D9)

- [x] 2.1 `Publication` aggregate: own identity, Position ref + lineage handles, audience/channel/format,
  delivery outcome, supersession links, immutability invariants. — `publication.go`: immutable content +
  mutable delivery status (Pending→Delivered/Failed, idempotent) + set-once supersession + retention
  `PrunePayload` (regenerable), optimistic `version`.
- [x] 2.2 Materialization rule: Position → artifact with the **stance-equality invariant** (pure,
  deterministic). — `materialize.go`: `Materialize(PositionSnapshot, ArtifactType)` carries the stance
  verbatim (invariant proven across all stances×types); deterministic re-render; `Stance` mappings
  (Phrase / VEXStatus) are presentation of the same conclusion.
- [x] 2.3 Communication events (`PublicationCreated` / `Published` / `Delivered` / `Superseded`) as
  terminal completed facts. — `event.go` (Created / Delivered / Superseded; thin, terminal — never upstream).
- [x] 2.4 Unit tests: immutability, stance-equality, supersession chain, deterministic re-render, event
  shapes. — 100% coverage.
- [x] 2.5 Gate: build + unit tests + coverage green; clean-architecture green. — domain 100%; lint + arch green.

## 3. Serializer registry (COMM-05 · D7)

- [x] 3.1 Serializers: VEX (CycloneDX / OpenVEX), advisory (CSAF + human-readable), audit report
  (structured), notification (channel-native); extensible registry. — `adapters/serializer`: `Serializer`
  interface + `Registry` (`Render(format, Artifact)`, `Default()` with 6 built-ins); each reads only the
  abstract `domain.Artifact` (no external-format leak into the domain).
- [x] 3.2 Golden-file tests per format. — byte-exact golden per format + determinism (re-render identical) +
  stance→status/product_status mapping across all bands.
- [x] 3.3 Gate: six Themis gates green. — serializer 100%.

## 4. Inbound seam + human-triggered publish + persistence (COMM-06, COMM-07, COMM-09 · D2/D4/D5/D9)

- [x] 4.1 Inbound: consume `PositionEstablished` / `PositionRevised`, fetch via Governance read API,
  Positions only; update publishable-positions queue / mark stale. — `adapters/inbound.Consumer` (decodes
  Governance's wire events, no cross-context import) → `RecordPublishable` (Established=ready, Revised=stale);
  `adapters/governance.Client` implements the `PositionReader` port (`GetPosition` via `GET /findings/{id}`).
- [x] 4.2 `app`: human-triggered `CreatePublication` — materialize (D3) + record immutable Publication +
  supersede prior; optimistic concurrency. — fetch Position → `Materialize` → serialize → record + supersede
  the current Publication for (Release, Faultline, type, audience); retry-on-conflict loop.
- [x] 4.3 `adapters/store`: Postgres Publication aggregate (record + capped payload + supersession +
  version) + outbox + projections; aggregate-root load/store. — `publications` (nullable-payload = pruned) /
  `communication_outbox` / `publishable_positions`; version-guarded supersede → ErrConcurrent; transactional
  outbox.
- [x] 4.4 Integration tests: Position → queued (no auto-publish); trigger → recorded Publication; revise →
  supersede; migration up/down. — embedded-Postgres suite (round-trip, supersede + optimistic concurrency,
  publishable-queue upsert, purge, down/up) + app tests (fakes) + inbound consumer tests (wire JSON).
- [x] 4.5 Gate: six Themis gates green. — app 100%, store 80.6%, governance-client 95.5%, inbound 100%.

## 5. Delivery + read side (COMM-08, COMM-10, COMM-12 · D6/D10)

- [x] 5.1 Delivery: channel-per-artifact via transactional outbox (exactly-once, idempotent, retried);
  routing rules + digest; redaction; delivery outcome recorded. — `DeliveryService.DeliverPending` drains the
  durable pending/failed queue via a `Deliverer` + `Redactor` port (idempotent `MarkDelivered`, failed→retry,
  outcome recorded + `PublicationDelivered`); `store.Relay` for terminal audit events; `adapters/delivery`
  ships a logging channel + pass-through redactor (concrete SMTP/Slack/webhook + routing/digest reuse the PoC
  notify, **deferred**).
- [x] 5.2 `app`: read side — `GetPublication` (regenerate payload if pruned) / `ListPublications`;
  publishable-positions + release-posture projections; non-recording preview. — `ReadService` (regenerates a
  pruned payload deterministically from the persisted artifact + serializer, no Governance re-fetch); `Preview`
  renders without recording.
- [x] 5.3 `adapters/http`: publish-trigger + read/preview API — trigger publication, get/list publications,
  preview, queue; error-UX envelope. — spec-first oapi-codegen (`api/communication.openapi.yaml`,
  `make generate-api-communication`) + `wiring`; Problem envelope. 100%.
- [x] 5.4 Integration tests: delivery exactly-once + retry; preview does not record. — store delivery-queue +
  update + relay retry integration; app delivery tests (fail→retry, idempotent skip); preview never writes.
- [x] 5.5 Gate: six Themis gates green. — app 100%, http 100%, store 81.3%, delivery 100%.

## 6. Workers + coordinator + recovery + retention (COMM-11 · D11)

- [x] 6.1 Workers (inbound-queue, delivery relay, projection builder, retention/pruning) + non-owning
  coordinator (app services only). — `adapters/inbound.Consumer` (inbound-queue worker → `RecordPublishable`,
  the non-owning coordinator for the inbound flow), `DeliveryService` + `store.Relay` (delivery + terminal
  events), `RetentionService` + `store.PrunePayloads` (retention). `cmd/communication` runs the API + a
  delivery/reconcile/prune worker loop + a pre-M5 event-intake endpoint.
- [x] 6.2 State-based recovery: idempotent re-run + first-class reconciler (no replay); human-trigger +
  in-flight delivery held as durable state. — `ReconcileService.Reconcile` drains the terminal-event outbox;
  undelivered Publications resume from the durable pending status (idempotent re-run); the publishable-queue
  holds pending human triggers.
- [x] 6.3 Crash/resume tests: pending trigger never lost / never auto-published; undelivered resumes. —
  `TestCrashResumeUndeliveredAndQueue` (store): a fresh Store re-reads the pending Publication + the queued
  position; nothing was auto-published or auto-delivered. `TestPrunePayloadsRetention` proves regenerable
  pruning.
- [x] 6.4 Gate: six Themis gates green; `markdownlint-cli2` clean. — full `make check` = exit 0.
