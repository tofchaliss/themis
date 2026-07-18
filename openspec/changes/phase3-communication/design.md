# Design — phase3-communication (Communication bounded context)

## Source of truth

All engineering decisions (rationale + rejected alternatives) live in
**`docs/engineering/decisions/EDR-COMMUNICATION-01.md` (D1–D12)**. This document states layout, import
rules, persistence, the inbound seam, and gates only.

## Layout (D12 · ADR-BCK-0037; Book III §3.2)

Context-first, three rings, same Go module, mirroring the Evidence/Knowledge/Governance template:

```text
internal/communication/
├── domain/     Publication aggregate (identity, Position reference, lineage handles, audience/channel/
│               format, materialized-artifact abstraction, delivery outcome, supersession links,
│               immutability invariants); materialization rule (Position → artifact, stance-equality
│               invariant, pure); Communication events
├── app/        CreatePublication (human-triggered), Preview, GetPublication/ListPublications, Reconcile,
│               Prune + ports (Governance read-API client, Position-event subscription, serializers,
│               delivery channels, outbox, aggregate repository, projection store, routing rules)
└── adapters/   Governance read-API client, inbound Position-event consumer, serializers (CycloneDX/OpenVEX/
                CSAF/report/channel-native), delivery channels (email/Slack/webhook/export), store
                (Postgres aggregate + capped payload + outbox + projections), http (publish-trigger +
                read/preview API), workers
```

## Import rules (ADR-BCK-0037/0038/0039; Book III §3.5)

- `domain/` imports nothing; `app/` imports `domain/`; `adapters/` import `app/` + `domain/`.
- **No cross-context imports.** Communication collaborates only via events + read APIs; it consumes
  Positions through Governance's read API, never its tables. Enforced by `go-cleanarch` + depguard + an
  architecture test.

## Persistence (D9)

- The **Publication is the aggregate root** = identity + Position-version reference + lineage handles +
  audience/channel/format + capped payload + delivery outcome + supersession links; loaded/saved whole
  (BCK-0042). Content is immutable; only **delivery status** mutates under **optimistic concurrency**
  (BCK-0043).
- **Lineage metadata is permanent** (CON-0016); the **rendered payload is capped + regenerable** from the
  Position version + serializer (D1). Disposable **projections** for the publishable-positions queue and
  release posture (BCK-0047).
- Recording a Publication + its delivery note is atomic; delivery via the **shared transactional outbox**
  (BCK-0041 / M5), exactly-once, idempotent per (Publication, channel).

## Cross-context seam (in, from Governance)

Subscribe to `PositionEstablished` / `PositionRevised`; fetch the full Position via Governance's read API
(`GetPosition`), never its tables; consume **Positions only** (DOM-0025). `PositionRevised` marks prior
Publications stale + queues re-publish (D5). Communication emits **terminal** events only, never upstream.

## Stack

Canonical stack + rationale: **`docs/engineering/STACK.md`** (read before implementing).
Communication-specific: **pgx** + **golang-migrate** (Publication aggregate + capped payload + outbox +
projections), a **serializer registry** (CycloneDX VEX / OpenVEX / CSAF / channel-native), **delivery
channels** (SMTP / Slack / webhook) carried over from the PoC `notify`, a **Governance read-API client**,
**OpenTelemetry** + **zap**.

## Quality gates

The six Themis gates (`make check`) — build, unit tests, coverage, dead-code, integration tests,
clean-architecture — extended to `internal/communication/`. Markdown passes `markdownlint-cli2`.
