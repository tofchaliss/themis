# EDR-COMMUNICATION-01 — Communication Bounded Context

Status: **Grilled — ready for issue breakdown** (12 decisions locked, 2026-07-15). Ground rule: ADR wins;
the `internal/` PoC is reference only.

## Purpose

Convert the Communication ADR cluster (CON-0010, DOM-0025, CON-0002, CON-0003, CON-0015, CON-0016, CON-0012,
CON-0001, DOM-0033, BCK-0037, BCK-0041, BCK-0047) into concrete, testable engineering decisions for the
Phase-3 greenfield rebuild.

Communication is the **publication** context. It materializes Governance's **Enterprise Positions** into
audience-specific artifacts (VEX documents, advisories, customer notifications, audit reports, executive
summaries) and **never modifies, establishes, or reinterprets** enterprise truth (CON-0010, DOM-0025). It
consumes `PositionEstablished` / `PositionRevised` (+ Governance's read API) and is the terminal stage of
the Evidence → Knowledge → Governance → Communication pipeline.

## Decisions

### D1 — Communication owns a first-class recorded Publication (permanent lineage, capped regenerable payload)

Decision:

- Communication owns a first-class **Publication** artifact. Each materialized output (VEX document,
  advisory, customer notification, audit report, executive summary) is an **immutable record with its own
  stable internal identity**, capturing: **which Position version** it materialized, the **audience +
  channel + format**, **when/where** it was published + the delivery outcome, and the **full lineage link**
  (Position → Finding → Faultline → Evidence).
- **Not render-and-forget.** On-demand live rendering (the PoC's live VEX export) is retained as a
  **preview/read path**, not an act of publication; an actual publication is **recorded**.
- **Retention cap, reconciled with CON-0016:** the Publication's **lineage record** (metadata — Position
  version reference, audience/channel/format, timestamps, lineage links, delivery outcome) is **permanent**;
  CON-0016 requires the published-Communication lineage to be part of the permanent enterprise record and
  forbids dropping it. The **heavy rendered payload bytes** (the full VEX/advisory/report document) are
  subject to a **retention cap** and pruned beyond it, because materialization is **deterministic** — the
  exact bytes are **regenerable on demand** from the immutable Position version (D-materialization) + the
  lineage. So: **metadata permanent, payload capped + reproducible.**
- Identity: own internal ID (provenance, not identity). Re-publish / revision semantics are deferred to a
  later decision.

ADR basis: CON-0016 (permanent, reconstructable lineage; Communication preserves complete decision
lineage), CON-0010 (Communication generates/publishes artifacts, consumes authoritative state, never
modifies), DOM-0025 (materializes Positions into audience artifacts), Book II §8.7 (artifact types).

Honesty flag: the first-class recorded Publication is ADR-driven (CON-0016). The **payload retention cap**
is an engineering/ops choice, ADR-safe **only** because the lineage metadata stays permanent and the payload
is deterministically regenerable — a cap that dropped the lineage record itself would violate CON-0016.

PoC contrast: the PoC's VEX export is stateless (live `GET …/vex`) and notifications are delivery jobs; the
greenfield records Publications with permanent lineage and capped, regenerable payloads.

### D2 — Inbound seam: subscribe to Position events, fetch via Governance's read API, Positions only

Decision:

- Communication **subscribes to Governance's `PositionEstablished` / `PositionRevised`** events (thin
  payload) and **fetches the full Enterprise Position** (stance, rationale, version, lineage handle) through
  Governance's read API (`GetPosition`), never Governance's tables (Book III §3.5). Event-driven, not
  polling (DOM-0033, CON-0012).
- **Positions only** (DOM-0025): it never subscribes to Finding/Proposal events and never treats a Finding
  or Proposal as publishable truth.
- **Lineage** (CON-0016): it records the Position's **reference handles** (Finding ID → Faultline ID →
  Evidence); the deeper chain stays **reconstructable by traversal** — Communication does not copy or
  re-own upstream state (CON-0001). It keeps no copy of Governance state beyond the lineage reference and
  the Publication record (D1).

ADR basis: DOM-0025 (Positions only), CON-0012 (event-driven collaboration), DOM-0033 (react to
completed-fact events), CON-0016 (lineage references), CON-0001 (single ownership; no re-owning), Book III
§3.5 (read API, not shared tables), BCK-0047 (read API). Contract: EDR-GOVERNANCE-01 D8/D10
(`PositionEstablished` / `PositionRevised` + `GetPosition`).

PoC mapping: the PoC's VEX export / notifications read `risk_context` directly (shared tables); the
greenfield consumes Position events + Governance's read API instead.

### D3 — Deterministic materialization into four audience artifacts; the stance is never reinterpreted

Decision:

- On a Position (D2), Communication **materializes** it into one or more audience-specific artifacts.
  **Current scope — four artifact types:**
  - **VEX document** — machine-readable, for security tooling / SBOM consumers (CycloneDX VEX, OpenVEX).
  - **Security advisory** — human-readable, customer-facing.
  - **Customer notification** — email / Slack / webhook alert.
  - **Audit report** — compliance / internal.
  - (Executive summary and other future audiences are **out of current scope**; the materializer set is
    extensible — a new audience is a new materializer, like adding a format.)
- Materialization is a **pure, deterministic transform** of `Position (+ lineage) → artifact bytes`.
- **Hard invariant:** the **stance in every artifact equals the Position's stance** — no artifact may state
  a different conclusion (CON-0010 / DOM-0025). Presentation (format, audience, wording) may vary; the
  conclusion may not. E.g. *Not Affected* → VEX `not_affected` + advisory "not affected"; *Affected +
  Mitigated* → VEX `affected`/`fixed` + advisory with remediation. Successor to the PoC's
  `MapDecisionToVEXStatus` / `vexgen`.
- **Which** artifacts are produced for a given Position is a **materialization policy** (per audience /
  channel config) — a selection, not a reinterpretation.
- Determinism makes D1's payload **regenerable** — re-running materialization on the same Position version
  yields identical bytes.

ADR basis: CON-0010 (transform presentation / select audience / generate reports; never modify or
reinterpret), DOM-0025 (re-present, never reinterpret; materialize into VEX/advisories/notifications/
reports), Book II §8.7 (artifact types), CON-0003 (explainable — the artifact carries lineage).

PoC mapping: `vexgen` (`cyclonedx.go` / `openvex.go`), notification digests, and VEX export map to the VEX
and notification materializers; the **advisory** and **audit report** are new first-class materializers.

### D4 — All communication artifact creation is human-triggered (no automation, for the time being)

Decision:

- **No automatic materialization or publication.** Every communication artifact (VEX document, security
  advisory, customer notification, audit report) is created and published **only on an explicit manual
  trigger by a human**.
- The inbound Position event (D2) does **not** auto-produce an artifact; it marks the Position as
  **available/ready to publish** (a "publishable positions" work queue / read model). A human works from
  that queue and explicitly triggers creation of a chosen artifact type for a chosen Position → materialize
  (D3) → record Publication (D1) → deliver.
- Communication never invents authority and never publishes without a human trigger (CON-0010, CON-0015).
  The **content** is still fixed by the Position (D3 invariant); the human authorizes the **act of
  publishing**, not the conclusion.
- **Deferred ("for the time being"):** a Governance-defined **delegated auto-publish policy** (routine
  machine artifacts published automatically within delegated authority) is explicitly **out of current
  scope**. It is added later without changing the model — it becomes an alternate **trigger source**
  alongside the human trigger.

ADR basis: CON-0015 (human authority over automation; automation never independently establishes customer
communication), CON-0010 (materializes authoritative state, never creates authority), DOM-0025 (consumes
Positions).

Honesty flag: CON-0015 mandates human authority and forbids automation **independently** establishing
customer communication. Requiring a human trigger for **all four** artifact types (including machine/internal
VEX + audit report) is **stricter** than CON-0015 strictly requires — a deliberate initial-scope choice
("for the time being"), fully ADR-compatible (more conservative), with the delegated-auto-publish path left
open for later.

PoC contrast: the PoC auto-generates VEX on a triage decision and auto-dispatches notifications on events;
the greenfield makes all artifact creation human-triggered initially.

### D5 — Publication revision by append-and-supersede (immutable history)

Decision:

- A revised Position **never edits a prior Publication** (immutable, D1).
- On `PositionRevised` (D2), Communication marks that Position's prior Publications **stale** and flags the
  Position for **re-publication** in the human queue (D4) — **no auto-republish**.
- A human triggers a **new Publication** from the new Position version; it **supersedes** the prior one: the
  old record gets `supersededBy → <new>`, the new gets `supersedes → <old>`. **Both are kept** (CON-0016) —
  the full "what we told whom, when, off which decision version" history stays intact.
- The **"current" published artifact** for a given (Release, Faultline, artifact-type, audience) is the
  **latest non-superseded Publication**; identity stays each Publication's own ID.
- **Append-and-supersede, never mutate** — the same shape as Governance Position versioning and Evidence
  immutability.

ADR basis: CON-0016 (permanent, reconstructable lineage; history survives), CON-0010 (re-publish updated
truth, never rewrite the decision), DOM-0025 (Positions drive re-publication), CON-0003 (explainable
history). Mirrors EDR-GOVERNANCE-01 D3 (Position versioning) and Evidence immutability.

PoC contrast: the PoC re-renders VEX live (no supersession history) and re-sends notifications; the
greenfield keeps an immutable superseding Publication chain.

### D6 — Channel-per-artifact-type delivery via the transactional outbox (exactly-once, idempotent, recorded)

Decision:

- **Channel per artifact type:**
  - **VEX document** → made available for **retrieval/export** (fetchable record; optionally attached).
  - **Audit report** → **retrieval/export** (internal/compliance).
  - **Customer notification** → **pushed** via email / Slack / webhook (the PoC's channels).
  - **Security advisory** → published to a **customer-facing surface** (+ optional notification).
- **Delivery is decoupled from materialization via the transactional outbox** (BCK-0041): recording the
  Publication **+** a delivery note is one atomic write; a background sender delivers, marks done, and
  **retries on failure** — every recorded Publication is delivered **exactly-once-eventually**, and nothing
  is delivered that was not recorded. Delivery is **idempotent** (keyed by Publication ID + channel; retries
  never double-send).
- **Recipient selection** uses routing rules (audience/channel by product/severity — the PoC's
  `notification_rules`), with **digest batching** for notifications. Per D4 the human triggers publication;
  routing then resolves who/where for that triggered artifact.
- **Delivery outcome** (delivered / failed / retrying) is recorded on the Publication for traceability
  (CON-0016); **sensitive content is redacted** before external delivery (the PoC's `redact`).

ADR basis: BCK-0041 (transactional outbox, exactly-once-eventually), CON-0016 (delivery outcome part of the
permanent record), CON-0010 (select audience/channel), DOM-0033 (delivery notes as recorded facts). Mirrors
Evidence D7 / Governance D8 outbox.

PoC mapping: `adapter/notify` (`routing.go`, `digest.go`, `retry.go`, `redact.go`, `smtp.go`, `teams.go`,
`enqueue.go`, `job.go`) is the delivery machinery — reused **downstream of a human trigger**; the
`notification_rules` table = routing rules.

### D7 — Extensible serializer registry; standards-first output formats

Decision:

- Each artifact type has a **serializer** rendering it into concrete bytes, via an **extensible serializer
  registry** (the outbound mirror of Evidence's inbound parser ACL — adding a format is one localized
  change; the domain holds the artifact abstractly, serializers render out, external format shapes never
  leak in).
- Formats (**standards-first**):
  - **VEX document** → **CycloneDX VEX** + **OpenVEX** (the PoC's `vexgen`).
  - **Security advisory** → **CSAF** (the machine-readable advisory standard) + a **human-readable
    rendering** (Markdown/HTML).
  - **Audit report** → a structured report (HTML/PDF, or structured JSON).
  - **Customer notification** → **channel-native** (email body, Slack message, webhook JSON).
- Standards-first wherever one exists, so downstream tooling ingests the output directly.

ADR basis: BCK-0052-style ACL (outbound serializer boundary; no external-format leak into the domain),
CON-0010 (transform presentation into consumable formats), Book II §8.7. Mirrors Evidence D4 (standards
only, extensible registry) in reverse.

PoC mapping: `vexgen/cyclonedx.go` + `openvex.go` are the VEX serializers; advisory CSAF and the audit
report are new serializers; the `notify` channel formatters (`smtp` / `teams` / webhook) are the
notification serializers.

### D8 — Thin terminal audit events; one-way flow preserved

Decision:

- Communication emits **thin completed-fact events** via the shared outbox (BCK-0041): `PublicationCreated`,
  `PublicationPublished` / `PublicationDelivered`, `PublicationSuperseded`.
- **Terminal / audit events:** consumers are the **audit log, metrics/observability, and (optionally)
  external integrations** (e.g. a SIEM). They are **never consumed by an upstream context** — the one-way
  directional flow is preserved (CON-0001, Book I §9.7).
- The events establish **no new truth** (CON-0010); they announce that a materialization/delivery **fact**
  occurred. With the Publication record (D1/D6) they complete CON-0016's permanent, reconstructable record.

ADR basis: DOM-0033 (completed-fact events after a state change), CON-0016 (published facts part of the
permanent record), CON-0010 (no new truth), CON-0001 + Book I §9.7 (one-way flow — no feedback upstream),
BCK-0041 (shared outbox). Same event pattern as Evidence/Governance, distinguished by being **terminal**.

PoC mapping: the PoC emits internal notification events and logs deliveries; the greenfield formalizes
**terminal Publication events** for audit/metrics.

### D9 — Publication as its own aggregate root (immutable content + mutable delivery status), optimistic concurrency

Decision:

- The **Publication is the aggregate root** and consistency boundary (DOM-0031): identity + the
  Position-version reference + lineage handles + audience/channel/format + the materialized payload (capped,
  D1) + delivery outcome + supersession links (D5). Loaded/saved as one unit (BCK-0042). Recording a
  Publication **+** its outbox delivery note is **atomic** (D6).
- **Each Publication is its own aggregate**, related to others only by **supersession links** (D5) — not
  nested in a per-(Release, Faultline) parent — because each artifact is an independent immutable record
  with its own delivery lifecycle. "Current" is a query (latest non-superseded), not parent state.
- **Concurrency is light:** content is immutable; the only mutation is **delivery status**
  (delivered/failed/retrying). An **optimistic version stamp** (BCK-0043) lets concurrent delivery-retry
  workers converge without double-send (aligned with D6's idempotent delivery).
- **Payload storage:** the capped, regenerable payload sits alongside the record, pruned by retention,
  regenerable from the Position version + serializer (D1/D7). The **"publishable positions" queue** (D4)
  and rollup reads (D10) are **projections** from inbound Position events + Publication events — not
  aggregate state.

ADR basis: DOM-0031 (aggregate = consistency boundary), BCK-0042 (aggregate-root repository), BCK-0043
(optimistic concurrency on delivery status), CON-0016/CON-0003 (immutable recorded content), BCK-0047
(projections). Same persistence discipline as Evidence/Knowledge/Governance, adjusted for a mostly-immutable
artifact.

PoC contrast: the PoC has no Publication aggregate (VEX rendered live; notifications as delivery jobs); the
greenfield persists immutable Publications with a guarded delivery status.

### D10 — Read side: direct `GetPublication` / `ListPublications` + projections + non-recording preview

Decision:

- **Direct reads on the aggregate store:**
  - **`GetPublication`** (by ID) → the record + lineage + delivery outcome; payload served from store, or
    **regenerated on the fly** if pruned (D1/D9).
  - **`ListPublications`** by Release / Position / Faultline; **"current"** = latest non-superseded per
    (Release, Faultline, artifact-type, audience) (D5).
- **Projections** (disposable, event-built — BCK-0047):
  - **Publishable-positions queue** (D4) — the analyst worklist: Positions ready to publish or gone stale
    (need re-publish), from inbound `PositionEstablished` / `PositionRevised` + Publication events.
  - **Release communication posture** — what has been published for a Release, and where the gaps are.
- **Live preview** (D1) — render a Position to an artifact **without recording** (distinct from an act of
  publication).
- Projections never mutate aggregates and are rebuildable from events; by-ID reads hit the aggregate store.

ADR basis: BCK-0047 (event-built disposable read models; aggregates authoritative), CON-0016
(lineage-complete reads), CON-0003 (explainability). Mirrors Evidence D8 / Knowledge D10 / Governance D10.

PoC mapping: the PoC's live VEX export = the preview path; the greenfield adds the publishable-positions
queue + release-posture projections and recorded Publication reads.

### D11 — Workers + non-owning coordinator; state-based recovery; human-trigger + in-flight delivery durable

Decision:

- **Workers** (BCK-0045, each modifies only Communication aggregates):
  - **inbound Position-event consumer** → updates the publishable-positions queue / marks stale (D2/D5);
    does **not** auto-materialize (D4);
  - **delivery worker(s)** → the outbox relay pushing artifacts per channel, retrying (D6);
  - **projection builders** (D10);
  - a **retention/pruning worker** → caps payload storage, keeps metadata (D1).
- A **coordinator** (BCK-0044) sequences the human-triggered flow (human trigger → materialize → record →
  deliver) by calling **app services only**; it waits for the human trigger, then drives materialize →
  deliver; it never mutates aggregates or enforces rules.
- **Recovery is state-based** (BCK-0050): **(1) idempotent re-run** — inbound Position events stay queued
  until acknowledged; delivery notes stay in the outbox until delivered; each step checks persisted state
  (Publication already recorded? already delivered?). **(2) a first-class reconciler** — inspects
  authoritative state (Publications recorded-but-undelivered; stale Positions never re-published; failed
  deliveries) and continues incomplete work. **No workflow-replay.**
- **Durability:** a pending human trigger is an unworked queue entry (never lost, never auto-actioned); a
  triggered-but-undelivered Publication is persisted, and a restart resumes delivery from the outbox.

ADR basis: BCK-0044 (coordinator sequences/waits/resumes, does not own), BCK-0045 (workers own only their
context), BCK-0050 (state-based recovery from persisted state; reconciliation first-class; replay rejected).
Idempotency mechanics from D6/D9.

PoC mapping: the PoC's `notify` `job` / `retry` / `enqueue` are the delivery workers; the greenfield adds
the inbound-queue worker, the reconciler, and the retention worker, keeping publication human-triggered.

### D12 — Context-first three-ring layout mirroring the Evidence/Knowledge/Governance template

Decision:

- Communication is a self-contained tree **`internal/communication/{domain,app,adapters}`** in the same Go
  module; dependencies inward-only; **no cross-context imports** — collaboration solely via events + read
  APIs (D2/D8); enforced by `go-cleanarch` + an architecture test.
- **`domain/`** (pure, depends on nothing): the Publication aggregate (identity, Position reference, lineage
  handles, audience/channel/format, the materialized-artifact abstraction, delivery outcome, supersession
  links, immutability invariants); the materialization rule (Position → artifact, with the D3
  stance-equality invariant, pure); Communication events.
- **`app/`**: use cases (`CreatePublication` [human-triggered], `Preview`, `GetPublication` /
  `ListPublications`, `Reconcile`, `Prune`); ports for the Governance read-API client, Position-event
  subscription, serializers, delivery channels, outbox, aggregate repository, projection store, routing
  rules.
- **`adapters/`**: Governance read-API client, inbound Position-event consumer, serializers
  (CycloneDX/OpenVEX/CSAF/report/channel-native), delivery channels (email/Slack/webhook/export), store
  (Postgres aggregate + capped payload + outbox + projections), http (publish-trigger + read/preview API),
  workers.
- **Own database/schema — no shared tables** (Book III §3.5). Same Go module, new top-level context folder.

ADR basis: BCK-0037 (source mirrors bounded contexts), Book III §3.2 (context-first), BCK-0038/0039
(inward-only; domain depends on nothing), Book III §3.5 (events + read APIs, no shared tables). Same
template as Evidence D9 / Knowledge D12 / Governance D13.

PoC contrast: the PoC is technical-layer-first (`domain` / `usecase` / `adapter` shared across everything);
the greenfield is context-first with Communication isolated behind events + read APIs.

## Traceability → issues

One issue per implementable decision; each cross-references its decision + ADR. Suggested delivery: an
OpenSpec change `openspec/changes/phase3-communication/` with these as `tasks.md` groups.

| # | Issue | Realizes |
| --- | --- | --- |
| COMM-01 | Scaffold `internal/communication/{domain,app,adapters}`; wire `go-cleanarch` + architecture test (inward-only, no cross-context imports) | D12 · BCK-0037 |
| COMM-02 | `domain`: Publication aggregate — own identity, Position ref + lineage handles, audience/channel/format, delivery outcome, supersession links, immutability invariants (+ tests) | D1·D5·D9 · CON-0016/DOM-0031 |
| COMM-03 | `domain`: materialization rule — Position → artifact with the stance-equality invariant (pure, deterministic) (+ tests) | D3 · CON-0010/DOM-0025 |
| COMM-04 | `domain`: Communication events (`PublicationCreated`/`Published`/`Delivered`/`Superseded`) as terminal completed facts | D8 · DOM-0033 |
| COMM-05 | `adapters`: serializer registry — VEX (CycloneDX/OpenVEX), advisory (CSAF + human-readable), audit report, channel-native notification; extensible (+ golden tests) | D7 · BCK-0052 |
| COMM-06 | `app`+`adapters`: inbound seam — consume Governance `PositionEstablished`/`PositionRevised`, fetch via read API, Positions only; update publishable queue / mark stale | D2·D5 · DOM-0025 |
| COMM-07 | `app`: human-triggered `CreatePublication` — materialize (D3) + record immutable Publication + supersede prior; optimistic concurrency (+ tests) | D1·D4·D5·D9 · CON-0015/BCK-0043 |
| COMM-08 | `adapters`: delivery — channel-per-artifact via transactional outbox (exactly-once, idempotent, retried); routing rules + digest; redaction; delivery outcome recorded | D6 · BCK-0041 |
| COMM-09 | `adapters/store`: Postgres Publication aggregate (record + capped payload + supersession + version) + outbox + projections; aggregate-root load/store | D9 · BCK-0042 |
| COMM-10 | `app`: read side — `GetPublication` (regenerate payload if pruned) / `ListPublications`; publishable-positions queue + release-posture projections; non-recording preview | D10 · BCK-0047 |
| COMM-11 | Workers + non-owning coordinator; state-based recovery (idempotent re-run + first-class reconciler, no replay); retention/pruning worker (+ crash/resume tests) | D11 · BCK-0044/0045/0050 |
| COMM-12 | `adapters/http`: publish-trigger + read/preview API — trigger publication, get/list publications, preview, queue; error-UX envelope | D4·D10 · BCK-0048 |

## Glossary (this context)

- **Publication** — Communication's immutable record of one materialized artifact (VEX / advisory /
  notification / audit report) from one Enterprise Position version; own identity; permanent lineage
  metadata + capped, regenerable payload.
- **Materialization** — the deterministic transform of a Position (+ lineage) into artifact bytes;
  presentation may vary, the stance never (D3).
- **Artifact type** — VEX document / security advisory / customer notification / audit report (current
  scope; extensible).
- **Serializer** — the outbound renderer for a format (CycloneDX / OpenVEX / CSAF / report / channel-native);
  an extensible registry.
- **Publishable-positions queue** — the analyst worklist projection: Positions ready to publish or gone
  stale (need re-publish).
- **Supersession** — the append-and-supersede link chain that replaces a stale Publication after a Position
  revision; both records are kept.
- **Delivery** — channel-specific dispatch (retrieval/export, or push email/Slack/webhook) via the
  transactional outbox; exactly-once, idempotent, outcome recorded.
- **Preview** — a non-recording live render of a Position to an artifact; not an act of publication.
- **Lineage** — the recorded reference chain Position → Finding → Faultline → Evidence (CON-0016);
  reconstructable and permanent.
- **Communication events** — `PublicationCreated` / `Published` / `Delivered` / `Superseded`; terminal
  completed facts for audit/metrics, never fed upstream.
