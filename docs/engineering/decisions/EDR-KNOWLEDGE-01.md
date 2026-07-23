# EDR-KNOWLEDGE-01 — Knowledge / Faultline Bounded Context

Status: **Grilled — ready for issue breakdown** (12 decisions locked, 2026-07-14). Ground rule: ADR
wins; the `internal/` PoC is reference only.

Terminology note: the canonical term for a source's input is **Proposal** (CON-0002). Earlier drafts
used "claim" as a plain-English synonym; the EDR now uses **Proposal** throughout.

## Purpose

Convert the Knowledge/Faultline ADR cluster (DOM-0020, DOM-0021, CON-0002, CON-0003, CON-0008,
DOM-0026, DOM-0030, DOM-0033, BCK-0044, BCK-0045, BCK-0047, BCK-0050, BCK-0052) into concrete,
testable engineering decisions for the Phase-3 greenfield rebuild.

## Decisions

### D1 — A Faultline is one enterprise knowledge card per security issue, with its own identity

Decision:

- A Faultline is the enterprise's single knowledge card for one security issue. It has its own
  stable internal identity (an opaque ID, e.g. UUID). The identity is never the CVE string and never
  a source-prefixed string (no `NVD-CVE-...`).
- The canonical CVE ID is the Faultline's binding business key: the system finds-or-creates exactly
  one Faultline per canonical CVE. The CVE is stored as an alias/label on the card, not as identity.
- Non-CVE source labels (e.g. `ALPINE-CVE-...`, distro advisory IDs) are normalized to the canonical
  CVE before find-or-create, so one issue never yields two cards (reference: `domain.NormalizeCVEID`).
- Source/feed (NVD, OSV, Red Hat, Alpine, …) is provenance, never identity. Every source's report
  about a CVE converges on the one card as a source-tagged Proposal (CON-0002). The card's reconciled
  enterprise view is the authoritative knowledge.
- Affected package/version ranges are content on the card (a list of source Proposals), not part of
  its identity. A single Faultline may record many affected packages and ranges.
- Real-world per-release occurrences (this release ships this affected component) are Findings, owned
  by Governance; each references exactly one Faultline and is not stored on it (DOM-0020, Book II §6.5).

Cardinality policy (changeable): one Faultline ↔ one canonical CVE to start. Grouping several CVEs
under one card, or a pre-CVE advisory-only card, is left open and is not hard-wired into the identity.

ADR basis: DOM-0020 (enterprise-wide stable identity), DOM-0021 (Knowledge is sole owner), CON-0002
(proposal before truth — sources are Proposals, not truth), CON-0008 (evolve by enrichment, keep
history), CON-0003 (explainability — retain which source proposed what), BCK-0052 (an ACL translates
each feed into an enterprise Proposal).

PoC mapping: `vulnerabilities` (one row per CVE) ≈ card content; `component_vulnerabilities` /
`risk_context` (per artifact / component-version) ≈ Findings; the CR-3 provenance columns ≈ source
Proposals.

### D2 — The enterprise view is reconciled from Proposals by a fixed, explainable, source-agnostic rule

Decision:

- Every source Proposal is retained on the card and never overwritten. Each field of the enterprise
  view (headline severity / score, affected ranges, fix availability, …) is derived from the
  Proposals, not set by the last writer.
- Reconciliation uses a fixed, explainable precedence rule — not worst-case-highest and not
  newest-wins.
- The rule is context-aware: for a distro package (RHEL, Alpine, Rocky, Wolfi, …) that distro's own
  authoritative Proposal wins (it is backport-aware); otherwise the primary source (NVD) is used and
  other sources fill gaps. This carries over the PoC's distro-authoritative identity and Red Hat VEX
  overlay.
- The rule is source-agnostic. NVD, OSV, distro vendors, human analysts, and AI are all Proposal
  sources subject to Proposal Before Truth (CON-0002). AI has no special authority: an AI Proposal is
  advisory (non-authoritative) and only a rule or human governance may promote it — never promoted
  merely for being newest. The detailed AI ranking is deferred to EDR-INTELLIGENCE-01 (M4;
  INT-0056 advisory-only).
- Explainability: the card can always reconstruct why the enterprise view holds a value — which
  Proposals exist, which source won, and which rule applied (CON-0003).

ADR basis: CON-0002 (enterprise chooses truth by a deterministic rule; feeds / AI / humans are all
proposals), CON-0003 (explainable, reproducible), CON-0008 (enrichment preserves Proposals and
history).

PoC reference: CR-3 source-precedence merge (`component_vulnerabilities.source` / `source_severity` /
`source_cvss_*`), distro-authoritative correlation identity (v0.3.2–v0.3.3), Red Hat VEX overlay
(v0.3.5–v0.3.6).

Open (implementation): the exact ranked precedence table (which sources, in what order, per context)
is a small app-layer policy, enumerated during build.

### D3 — Knowledge owns correlation (SBOM matching) and emits a match fact; Governance creates the Finding

Decision:

- Matching a registered release's components against the cards (correlation) is owned by Knowledge,
  applying its own affected-range knowledge. This is ADR-stated: DOM-0021 and Book II §6.7 both list
  "correlation" as a Knowledge responsibility.
- The match is computed by a Knowledge background worker that touches only Knowledge-owned data
  (BCK-0045) and emits a completed business fact — a "match" domain event (DOM-0033).
- Governance consumes that event and creates the Finding and Enterprise Position. Knowledge never
  creates or owns Findings (DOM-0026: Governance owns Findings; Knowledge events may trigger
  governance workflows but Governance owns its own transitions).
- The match is a Proposal, not truth; Governance governs it into a Finding (CON-0002).
- The match does not mutate the Faultline. The card stays release-independent (D1). "Which releases
  are affected by card F" is at most a disposable read-model projection (BCK-0047), never card state.

ADR basis: DOM-0021 + Book II §6.7 (correlation is Knowledge's), DOM-0026 (Governance owns Findings;
events trigger, do not mutate), DOM-0033 (completed-fact event), BCK-0045 (worker, own-context only),
CON-0002 (match is a Proposal).

Honesty note: "Knowledge owns correlation" is ADR-stated; that this specifically includes
SBOM-component matching emitting a match event consumed by Governance is an ADR-consistent engineering
interpretation. The precise event shape is finalized in the Governance grill (the consumer side).

PoC reference: `usecase/correlation/correlator.go` produces the raw `component_vulnerabilities` rows
(the match); the greenfield lifts this to an emitted event rather than a shared table.

### D4 — Knowledge consumes Evidence event-driven, reads the inventory via Evidence's read API, keeps no copy

Decision:

- Trigger: Knowledge subscribes to Evidence's thin `EvidenceRegistered` event and acts on kind = SBOM.
  Event-driven, not polling (DOM-0033, DOM-0026).
- Read: on that event, Knowledge fetches the release's canonical component inventory through Evidence's
  official read API (`GetInventory`) — never Evidence's tables (Book III §3.5; the two contexts do not
  share a database). It reads only what matching needs (version-qualified purl, ecosystem, name).
- Keep no copy: Knowledge does not persist Evidence's inventory as its own state. Evidence is immutable
  (EDR-EVIDENCE-01 D3), so re-reads are byte-identical; duplicating it would make Knowledge a second
  owner of Evidence's data (DOM-0026 / single ownership). Reads are transient, per correlation run.
- The subject Release reference travels on the event; the match facts Knowledge emits are scoped to
  that Release (they feed the Governance Finding).

Deferred: handling of non-SBOM evidence (VEX vendor statements, scanner reports) as source Proposals
for the card is resolved in D6.

Contract / ADR basis: EDR-EVIDENCE-01 D6 (thin event) and D8 (`GetInventory` read API), DOM-0033 /
DOM-0026 (event-driven reaction), Book III §3.5 (read API, not shared tables), CON-0001 (single
ownership).

### D5 — Cards are created lazily, bounded by relevance (never a full feed mirror)

Decision:

- A Faultline is created when a CVE first becomes relevant to a component the enterprise has seen —
  never by mirroring the whole feed universe. The card population is bounded by "CVEs that affect
  components we have ingested," not "all CVEs in the world."
- Two lazy discovery paths create/enrich cards, differing only in trigger:
  1. SBOM-time — during correlation (D3/D4), query the feeds by package (PoC: OSV query-by-package)
     to discover relevant CVEs, then create/enrich the cards found.
  2. Scheduled watch — a background worker polls "which CVEs changed recently?" (PoC: NVD
     modified-since) and checks them against the set of already-known components, creating cards for
     new hits.
- Enrichment of a card's fields (CVSS, EPSS/KEV, exploit) is targeted per-card, not bulk.

Grounding: no ADR mandates eager vs lazy (verified by search) — it is an engineering choice, but not a
free one. The Constitution's relevance principle favours lazy: Book I §3.1–3.3 — a bare CVE is mere
information; it becomes relevant ("evidence") only when correlated with the enterprise's software, and
Knowledge is understanding of that relevant evidence. Consistent with DOM-0020 (a lazily-created card
is still enterprise-wide, reused across releases) and Book II §6.6.

PoC reference: `osv/component_fetcher.go` (query-by-package at scan time), `usecase/watch` (NVD
modified-since watch), NVD by-CVE backfill for targeted enrichment.

### D6 — One ACL per feed translating into a single common Proposal, typed by kind

Decision:

- Each external feed (NVD, OSV, Red Hat/CSAF, EPSS, KEV, ExploitDB, vendor VEX) has exactly one
  anti-corruption layer (ACL) that translates its dialect into the enterprise concept before it
  enters the domain (BCK-0052). External shapes never leak into Knowledge.
- Every ACL emits one common Proposal envelope: `{ source, observed-at, subject CVE, kind, payload }`.
  A Proposal is the canonical CON-0002 concept and is source-agnostic — feeds, AI, and humans all
  produce the same shape, so a new source is a new ACL and nothing on the card changes.
- Proposals are typed by a small fixed set of kinds (an engineering decomposition, not ADR-mandated),
  because reconciliation (D2) differs per kind:
  - `vuln-facts` — severity / CVSS, affected package + version ranges, fix versions (NVD, OSV, Red
    Hat, distros). Reconciled by precedence (severity) and union (ranges).
  - `exploit-signal` — EPSS score, KEV known-exploited, public-exploit-exists (EPSS, KEV, ExploitDB).
    Reconciled by latest / logical-or.
  - `applicability` — a vendor VEX "not affected / affected" for a package. Held on the card as
    knowledge; whether to honour it for a given release is Governance's decision (Proposal Before
    Truth), not Knowledge's.
- VEX arrives two ways and both become an `applicability` Proposal: uploaded evidence
  (`EvidenceRegistered` kind = VEX, read via Evidence's API — D4) or a Knowledge feed worker pulling
  an upstream VEX feed.
- The card's enterprise view is CON-0002's validated truth: Knowledge, the authoritative owner,
  reconciles the Proposals into it via the D2 precedence rule.

ADR basis: BCK-0052 (one ACL per feed; convert external → enterprise concept; no leak — verbatim),
CON-0002 (a single uniform Proposal applied equally to all sources — verbatim), CON-0003 (source and
time retained for explainability), CON-0008 (enrichment accumulates Proposals, preserves history).

Engineering-only (flagged): the kind typing (`vuln-facts` / `exploit-signal` / `applicability`) is a
reconciliation-driven decomposition, consistent with but not mandated by the ADRs.

PoC reference: adapters `nvd` / `osv` / `redhat` / `epsskev` / `exploitdb` / `vexfeed` each already
normalize to a domain type; the greenfield unifies them behind one Proposal envelope.

### D7 — Explicit Faultline lifecycle: Book II's five stages as a governed, forward-only ladder

Decision:

- The Faultline has an explicit lifecycle (DOM-0030) using Book II §6.6's five stage names:
  Created → Enriched → Correlated → Mature → Superseded.
- Modeled as a forward-only maturity ladder (monotonic, "highest milestone reached"), not a
  bounce-around machine:
  - Created — the card exists (first relevance established, D5).
  - Enriched — at least one source Proposal has been reconciled into the enterprise view (D2).
  - Correlated — at least one component match has been produced (D3).
  - Mature — corroboration criteria met (e.g. multiple independent sources agree / stable view). The
    exact threshold is implementation-open.
  - Superseded — terminal; the card was merged/replaced, or its CVE withdrawn/rejected upstream (NVD
    `REJECTED`); references redirect and it produces no new matches. Reachable from any stage
    ("where applicable," §6.6).
- Reaching a later milestone implies the earlier ones. Ongoing enrichment/correlation after a stage
  are recorded as events (`FaultlineEnriched`, match) and never regress the stage.
- Every transition is driven by a domain business operation (not a direct state edit) and emits a
  lifecycle event, giving a governed, auditable, reproducible history.

Why forward-only: Enriched and Correlated recur continuously and concurrently; a strict linear
back-and-forth machine would make transitions ill-defined and fight DOM-0030's "well-defined, governed
transitions." A monotonic ladder keeps transitions well-defined while events capture the ongoing
activity — satisfying DOM-0030 (explicit + governed + auditable) precisely.

ADR basis: DOM-0030 (explicit lifecycle; transitions via business operations; auditable and
reproducible), CON-0003 (explainable history), DOM-0033 (each transition is a completed-fact event).
Book II §6.6 supplies the five stage names (a descriptive list) instantiated here as a governed ladder.

Honesty flag: DOM-0030 mandating an explicit governed lifecycle is ADR-stated; the five stage names
are Book II §6.6's illustrative list. The forward-only ladder interpretation (and folding
withdrawn/rejected CVEs into Superseded) is the engineering choice that makes the five ADR-compliant
rather than a bounce-around machine.

Open: (a) the exact "Mature" corroboration threshold; (b) whether withdrawn/rejected CVEs get a
distinct terminal state or fold into Superseded (recommended: fold, to keep Book II's vocabulary).

### D8 — Knowledge publishes completed-fact events on state change (not per Proposal), thin, via the shared outbox

Decision:

- A published domain event fires only on an actual Faultline state transition — never on the mere
  arrival of a Proposal (DOM-0033: an event is "a completed business fact resulting from a successful
  state transition"; CON-0002: a Proposal is not itself truth).
- Recording is not publishing: every incoming Proposal is still persisted on the card for audit and
  explainability (CON-0003) and to feed corroboration for the Mature ladder (D7). A duplicate from the
  same source that changes nothing emits no event; a new independent source that shifts the view or
  advances corroboration does.
- Event set (thin payloads + read-API, mirroring Evidence D6; delivered via the shared transactional
  outbox, published only after atomic persist — BCK-0041 / M5):
  - `FaultlineCreated` — a new card exists.
  - `FaultlineEnriched` — the enterprise view changed (carries what changed, coarsely).
  - `FaultlineMatured` / `FaultlineSuperseded` — lifecycle transitions (D7).
  - `ComponentMatched` — the D3 correlation output (a release-component matches a card). Provisional
    name; the contract is finalized in the Governance grill (the consumer).
- Two downstream purposes (DOM-0026, "Knowledge events may trigger governance workflows"):
  `ComponentMatched` → Governance creates a Finding; `FaultlineEnriched` → Governance may re-evaluate
  existing Findings (knowledge evolution propagates — CON-0008).

ADR basis: DOM-0033 (events are completed facts from a successful state transition; publish after
persist — directly supports fire-on-change, not per-Proposal), CON-0002 (a Proposal is not truth),
CON-0003 (Proposals still recorded for explainability), DOM-0026 (Knowledge events trigger Governance),
CON-0008 (enrichment propagates), BCK-0041 (transactional outbox, exactly-once-eventually), BCK-0047
(read-API for details, thin events).

### D9 — One card-aggregate (append-only Proposals + materialized view + lifecycle), optimistic concurrency

Decision:

- The Faultline is one aggregate and one consistency boundary (DOM-0031): identity + an append-only
  list of Proposals + the materialized enterprise view + the lifecycle stage. Loaded and saved as a
  single unit through an aggregate-root repository (BCK-0042).
- Proposals are append-only and never overwritten (CON-0008 preserves history and explainability).
- The enterprise view is materialized (stored) state, recomputed by the D2 rule inside the same
  transaction whenever a Proposal folds in — not computed on read. The view is the enterprise truth,
  carries the lifecycle (DOM-0030), and is what events fire on (D8), so it is owned, auditable state.
- Concurrency is optimistic (BCK-0043): a version stamp on the card. Concurrent enrichers each
  load → append → reconcile → save; the first save wins, the rest hit a version conflict and retry.
  Proposals are additive and the D2 rule is deterministic, so retries converge — no lost updates and
  no locks.

ADR resemblance: DOM-0031 (aggregate = consistency boundary), BCK-0042 (aggregate-root repository),
BCK-0043 (optimistic concurrency), CON-0008 (append-only Proposals preserve history), DOM-0030
(lifecycle state on the aggregate). This is the same persistence shape Evidence adopted
(EDR-EVIDENCE-01 D7/D8).

Engineering-only (flagged): materialized-vs-derived view is ADR-silent; materialized is chosen because
the view is owned, lifecycle-bearing, event-emitting state.

### D10 — Read side: direct by-identity lookups on the aggregate store + disposable projections for rollups

Decision:

- Small read API:
  - `GetFaultline` (by ID or canonical CVE) → the enterprise view plus provenance (the Proposals and
    which one won — explainability, CON-0003), served directly from the authoritative aggregate store.
  - Rollup / cross-cutting queries (affected-releases, severity/product filters) served by disposable
    read-model projections built from Knowledge's own events (`ComponentMatched`, `FaultlineEnriched`).
- Projections never mutate aggregates, are eventually consistent, and are rebuildable from events
  (BCK-0047). Aggregate repositories remain authoritative.
- Only heavy rollups get a projection; simple by-ID / by-CVE reads hit the aggregate store — no
  projections we do not need.
- "Which releases are affected by card F" is release-facing data Knowledge does not own as card state
  (D3), so it is a projection, never aggregate state.

ADR basis: BCK-0047 (read models independent of aggregates, event-built, disposable, eventually
consistent; aggregates authoritative), CON-0003 (provenance on reads for explainability). Mirrors
Evidence D8 (separate read paths).

### D11 — Background workers + non-owning coordinator; state-based recovery (idempotent re-run + a first-class reconciler)

Decision:

- Workers (BCK-0045, each modifies only Knowledge aggregates):
  - per-feed pull/enrichment workers, each behind its ACL (D6);
  - a correlation worker reacting to `EvidenceRegistered` (D4);
  - a scheduled watch worker (D5).
- A coordinator (BCK-0044) sequences "new SBOM → correlate → enrich new cards → emit matches" by
  calling app services only; it never mutates aggregates or enforces business rules.
- Recovery is state-based (BCK-0050), realized two ways that together satisfy "reconciliation as a
  first-class capability":
  1. Idempotent re-run from durable inputs — the `EvidenceRegistered` event stays queued until
     acknowledged; the watch keeps a last-success watermark (PoC: `system_state.cve_watch_last_success`).
     On restart, each step checks persisted authoritative state before acting (match already exists?
     Proposal already folded at this card version?), so done work is a no-op. Dedup-by-identity +
     optimistic concurrency (D9) + exactly-once outbox (D8) make re-runs converge with no duplicates.
  2. An explicit first-class reconciler — a periodic job that inspects authoritative state (known
     inventories vs expected matches; card-enrichment currency) and continues incomplete work. This is
     BCK-0050's "reconciliation as a first-class capability," not reliance on message re-delivery alone.
- No workflow-replay log; recovery begins from persisted authoritative state and never invents state
  (BCK-0050, which rejects "replay entire workflow").

ADR basis: BCK-0045 (workers own only their context's aggregates), BCK-0044 (coordinator sequences,
does not own), BCK-0050 (state-based recovery from persisted authoritative state; reconciliation a
first-class capability; replay rejected). Idempotency mechanics (dedup, optimistic concurrency, outbox)
come from D8/D9.

Honesty note: "state-based recovery" is verbatim BCK-0050. "Idempotent re-run" is a valid realization
because idempotency is implemented as checking persisted state (= BCK-0050's "determine incomplete
work"); the explicit reconciler is included so the first-class-reconciliation clause is honored, not
retries alone.

### D12 — Context-first three-ring layout mirroring the Evidence template

Decision:

- Knowledge is a self-contained tree `internal/knowledge/{domain,app,adapters}` in the same Go module,
  copying the Evidence template (EDR-EVIDENCE-01 D9); dependencies point inward only; no cross-context
  imports — collaboration is solely via events + read APIs (D3/D4/D8); enforced by `go-cleanarch` + an
  architecture test.
- `domain/` (pure, depends on nothing): Faultline aggregate (identity, append-only Proposals,
  materialized enterprise view, lifecycle, invariants); Proposal value object + kinds; the
  reconciliation / precedence rule (pure); Knowledge events.
- `app/`: use cases — Fold-Proposal/Enrich, Correlate, Watch, Reconcile, GetFaultline; ports for feed
  clients, the Evidence read-API client, outbox, aggregate repository, projection store.
- `adapters/`: feed ACLs (nvd / osv / redhat / epsskev / exploitdb / vexfeed), Evidence read-API
  client, store (Postgres aggregate + outbox + projections), http read API, workers.

ADR basis: BCK-0037 (source mirrors bounded contexts), Book III §3.2 (context-first, not
technical-layer-first), BCK-0038/0039 (app→domain layering; domain depends on nothing). Same template
Evidence established.

## Traceability → issues

One issue per implementable decision; each cross-references its decision + ADR. Suggested delivery: an
OpenSpec change `openspec/changes/phase3-knowledge/` with these as `tasks.md` groups (mirroring
`phase3-evidence`).

| # | Issue | Realizes |
| --- | --- | --- |
| KNOW-01 | Scaffold `internal/knowledge/{domain,app,adapters}`; wire `go-cleanarch` + architecture test (inward-only, no cross-context imports) | D12 · BCK-0037 |
| KNOW-02 | `domain`: Faultline aggregate — own identity, CVE alias + normalization, append-only Proposals, materialized enterprise view, lifecycle ladder + invariants (+ invariant tests) | D1·D7·D9 · DOM-0020/0030/0031 |
| KNOW-03 | `domain`: Proposal value object + kinds + the reconciliation / precedence rule (pure, deterministic; distro-authoritative else NVD) (+ tests) | D2·D6 · CON-0002/0003 |
| KNOW-04 | `domain`: Knowledge events (Faultline Created/Enriched/Matured/Superseded, ComponentMatched) as completed facts | D8 · DOM-0033 |
| KNOW-05 | `adapters`: one ACL per feed (nvd/osv/redhat/epsskev/exploitdb/vexfeed) → common Proposal; extensible registry; helpful rejection (+ golden tests) | D6 · BCK-0052 |
| KNOW-06 | `app`: Fold-Proposal / Enrich use case — attach Proposal, reconcile view, advance lifecycle, publish on view-change via outbox; optimistic concurrency (+ concurrent-enrich test) | D2·D8·D9 · BCK-0041/0043 |
| KNOW-07 | `app` + `adapters`: correlation worker — on `EvidenceRegistered(SBOM)` read `GetInventory`, match components → Faultlines, emit `ComponentMatched` (idempotent) | D3·D4 · BCK-0045/0052 |
| KNOW-08 | `app`: lazy discovery — SBOM-time OSV query-by-package + scheduled watch (NVD modified-since + watermark) creating/enriching cards | D5 · CON-0008 |
| KNOW-09 | `adapters/store`: Postgres aggregate (card + append-only Proposals + view + lifecycle + version) + outbox + projections; aggregate-root load/store | D9 · BCK-0042 |
| KNOW-10 | `app`: read side — `GetFaultline` (view + provenance) from aggregate; disposable event-built projections for rollups (affected-releases, filters) | D10 · BCK-0047 |
| KNOW-11 | recovery — idempotent re-run from durable inputs + first-class reconciler (state-based, no replay) (+ crash/resume tests) | D11 · BCK-0050 |
| KNOW-12 | coordinator sequences new-SBOM → correlate → enrich → emit via app services only (no aggregate mutation) | D3·D11 · BCK-0044 |
| KNOW-13 | `adapters/http`: read API — GET faultline by id / CVE + rollup queries; error-UX envelope | D10 · BCK-0047 |

## Glossary (this context)

- Faultline — the enterprise's single knowledge card for one security issue; own internal identity,
  keyed by canonical CVE; enterprise-wide, independent of Product / Project / Release.
- Proposal (a.k.a. source claim) — the canonical CON-0002 concept: one source's non-authoritative
  input about a CVE, tagged with source + time + kind; reconciled by Knowledge into the enterprise
  view. Every source (feed, AI, human) produces the same shape.
- Proposal kind — `vuln-facts` / `exploit-signal` / `applicability`; selects how D2 reconciles it.
- ACL (anti-corruption layer) — the one-per-feed translator that converts an external dialect into a
  Proposal before it enters the domain (BCK-0052).
- Enterprise view — the card's reconciled, authoritative understanding, derived from its source
  Proposals by an explainable rule.
- Finding — a release-scoped occurrence (owned by Governance) that references exactly one Faultline;
  where package + version + release live. Not stored on the Faultline.
- Precedence rule — the fixed, context-aware, source-agnostic policy that derives each enterprise-view
  field from the card's Proposals (distro-authoritative for distro packages, else NVD). AI and humans
  are Proposal sources under it, with no automatic authority.
- Correlation — Knowledge's step of matching a registered release's components against the cards'
  affected ranges to discover occurrences.
- Match — the completed fact Knowledge emits when a component matches a Faultline; consumed by
  Governance to create a Finding. A Proposal, not truth; it does not mutate the card.
- Lifecycle (Faultline) — Created → Enriched → Correlated → Mature → Superseded; a governed
  forward-only maturity ladder where each transition is a domain operation emitting a lifecycle event.
- Knowledge events — `FaultlineCreated` / `FaultlineEnriched` / `FaultlineMatured` /
  `FaultlineSuperseded` / `ComponentMatched`; completed facts published on state change (not per
  Proposal) via the shared transactional outbox.
- Card aggregate — the Faultline as one consistency unit: identity + append-only Proposals +
  materialized enterprise view + lifecycle; saved/loaded whole, guarded by optimistic concurrency.
- Read model / projection — a disposable, eventually-consistent view built from Knowledge's own
  events for rollup queries; never authoritative, rebuildable from events (BCK-0047).
- Reconciler — a first-class periodic job that inspects persisted authoritative state and continues
  incomplete correlation/enrichment work; recovery begins from state, never replay (BCK-0050).
