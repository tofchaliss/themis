# EDR-GOVERNANCE-01 — Governance / Findings & Enterprise Position Bounded Context

Status: **Grilled — ready for issue breakdown** (13 decisions locked, 2026-07-15). Ground rule: ADR wins;
the `internal/` PoC is reference only.

Terminology note: the constitutional term **Proposal** (CON-0002, "Proposal Before Truth") appears in two
bounded contexts with different targets. A **Knowledge Proposal** is a source's claim about a CVE
(reconciled into a Faultline — EDR-KNOWLEDGE-01 D6). A **Governance Proposal** is a proposed decision about
a Finding (evaluated into an Enterprise Position). Unqualified "Proposal" in this EDR means **Governance
Proposal**. See D4.

## Purpose

Convert the Governance ADR cluster (CON-0009, CON-0002, CON-0003, CON-0001, DOM-0022, DOM-0023, DOM-0024,
DOM-0025, DOM-0026, DOM-0030, DOM-0033, BCK-0044) into concrete, testable engineering decisions for the
Phase-3 greenfield rebuild.

Governance is the **authority** context. It owns Findings and Enterprise Positions (CON-0009) and turns
Knowledge's *understanding* into the enterprise's *official decision*. It consumes Knowledge's
`ComponentMatched` (to open a Finding) and `FaultlineEnriched` (to re-evaluate), and produces Enterprise
Positions for Communication (DOM-0025).

## Decisions

### D1 — A Finding is a release-scoped governance record, one per (Release, Faultline), with its own identity

Decision:

- A Finding is Governance's record of how one security issue affects one specific Release. It has its own
  stable internal identity (an opaque ID, e.g. UUID). The identity is never the CVE, never the Faultline
  ID, and never a composite string.
- The Finding's binding business key is the pair **(Release, Faultline)**: the system finds-or-creates
  exactly one Finding per (Release, Faultline). The Faultline is referenced by its immutable identifier
  (DOM-0022 implementation impact), never copied onto the Finding.
- **Findings are release-specific; Faultlines are enterprise-global.** A Finding never exists without a
  Release (DOM-0022) and never owns knowledge — it points at the one global Faultline, which is reused
  across every Release that references it (Book II §7.3/§7.7, DOM-0026).
- The matched package(s) and versions that triggered the Finding are **content/context** on it (carried in
  from Knowledge's `ComponentMatched`), not part of its identity. One Finding may list several matched
  components for the same (Release, Faultline).
- Occurrence-level facts (which SBOM/evidence, which component version) are provenance references, not new
  Finding identities. The same CVE reaching a Release through two packages is **one** Finding listing two
  components, governed as one decision.

Cardinality policy (changeable): one Finding ↔ one (Release, Faultline) to start. If a single Release ever
needs genuinely different decisions for the same CVE on different packages, package-level sub-entries
inside the Finding are the escape hatch — left open, not wired into identity.

ADR basis: DOM-0022 (release-scoped; exactly one Release + one Faultline; referenced by immutable ID;
never independent of a Release), DOM-0020 (the referenced Faultline is enterprise-global), DOM-0026
(Governance owns Findings; they reference knowledge and evolve independently), CON-0009 (only Governance
establishes Findings), Book II §7.

PoC mapping: `risk_context` (PK `artifact_id`, `component_purl`, `cve_id`) is a finer-grained precursor;
the greenfield lifts identity from per-(image, package, CVE) to per-(Release, Faultline), with package
detail becoming content and **Release replacing artifact/image** (no Artifact entity — EDR-KERNEL-01 D2).

### D2 — Finding and Enterprise Position are two separate objects (investigation vs authority)

Decision:

- Governance models two distinct objects, per DOM-0023/DOM-0024:
  - **Finding** — the release-scoped concern and its investigation. Holds the Faultline reference (D1), the
    matched components (content), and an **investigation status** (Book II §7.5: Identified → Under
    Investigation → Position Established → Monitoring → Resolved → Archived). It carries context, not
    authority.
  - **Enterprise Position** — the authoritative, committed decision about that Finding. Belongs to exactly
    one Finding (DOM-0023). Holds the official stance (Book II §8.2 example values: Affected / Not Affected
    / Mitigated / Accepted Risk / Deferred / Under Investigation) plus rationale. Only Governance
    establishes or revises it (CON-0009, DOM-0023).
- A Finding may exist with **no Position yet** ("found, not yet decided"). A Position never exists without
  its Finding (DOM-0023).
- Separation of concerns: investigation can continue and evidence can change without disturbing the
  committed decision, and the decision can evolve (see D3 versioning) without rewriting the Finding
  (Book II §8.5, DOM-0023 rationale).

The PoC's single `effective_state` field is decomposed — workflow values become **Finding status**,
decision values become **Enterprise Position** values:

| PoC `effective_state` | Greenfield |
| --- | --- |
| `detected` | Finding status = Identified (no Position yet) |
| `in_triage` | Finding status = Under Investigation |
| `confirmed` | Enterprise Position = **Affected** |
| `false_positive` / `not_affected` | Enterprise Position = **Not Affected** |
| `accepted_risk` | Enterprise Position = **Accepted Risk** |
| `resolved` | Enterprise Position = **Mitigated/Resolved** (+ Finding status → Resolved) |
| `suppressed` | Enterprise Position = **Not Affected** (with suppression reason) |

ADR basis: DOM-0023 (Enterprise Position = authoritative decision, one per Finding, only Governance
sets/revises), DOM-0024 (Proposal → Evaluation → Accept/Reject → Enterprise Position; investigation
separate from authority), CON-0009 (Governance is sole authority), Book II §7.5 (Finding lifecycle) and
§8.2 (Position values).

### D3 — Enterprise Position evolves by append-only immutable versions (never overwrite)

Decision:

- Each change to the decision is a **new immutable Position version** (v1, v2, v3…). The latest version is
  the current position; every prior version is retained forever, never edited or deleted.
- Each version records: the **stance** value, the **rationale**, the **actor** that established it (analyst,
  rule, or AI via governance), the **timestamp**, and **references to the inputs it rested on** (the
  accepted Governance Proposal + the Faultline knowledge state at that time) so any past decision is fully
  reconstructable (CON-0003).
- Only Governance establishes or revises a Position (DOM-0023, CON-0009).
- The value set (Affected / Not Affected / Under Investigation / Mitigated / Accepted Risk / Deferred) is
  **controlled but extensible** — Book II §8.2 calls the values "examples rather than fixed vocabulary," so
  adding one later is a localized change.

ADR basis: DOM-0023 (only Governance revises; authoritative), Book II §8.5 (establish new versions, never
modify history; history preserved for audit/replay/compliance), §8.8 (evolve through versioning; historical
positions immutable), CON-0003 (explainable/reproducible — inputs retained), CON-0009 (sole authority).

PoC contrast: `risk_context` is a single mutable row (update-in-place via `updated_at`); the greenfield
keeps the full version history instead. The PoC's `triage_history` append-log is the closest precursor, but
it records human triage decisions, not authoritative Position versions.

### D4 — Decisions are made through first-class Governance Proposals (and "Proposal" is disambiguated)

Decision:

- A **Governance Proposal** is a first-class, recorded object: a proposed decision about a Finding, from any
  source — Knowledge evolution, security analyst, engineering, vendor advisory, or AI. No proposal is
  authoritative (DOM-0024, CON-0002).
- Lifecycle: **Proposed → Evaluated → Accepted/Rejected.** Accepting a proposal **establishes a new
  Enterprise Position version** (D3). Rejected and superseded proposals are retained as history, preserved
  **independently of Positions** (DOM-0024 implementation impact).
- Only Governance evaluates and accepts/rejects (CON-0009). AI and automation may **propose** but never
  **decide** (DOM-0024: "enables AI and future automation without granting decision authority").
- Terminology (pins the collision): the constitutional Proposal concept (CON-0002) has two context-specific
  objects — a **Knowledge Proposal** (a source's claim about a CVE, reconciled into a Faultline) and a
  **Governance Proposal** (a proposed decision about a Finding, evaluated into a Position). Unqualified
  "Proposal" in this EDR means the Governance Proposal.

ADR basis: DOM-0024 (proposal-before-position; recorded, evaluated, accepted/rejected; history preserved
independently; AI without decision authority), CON-0002 (Proposal Before Truth — the shared principle),
CON-0009 (only Governance decides), Book II §10.5 (proposal sources).

PoC mapping: the PoC's triage decisions (`usecase/triage`; `triage_history` rows —
`false_positive` / `accepted_risk` / `confirmed` / `resolved` / `escalate`, each with justification +
actor) are human-analyst Governance Proposals, but the PoC applies them **directly** to `effective_state`
with no explicit proposed → accept/reject step. The greenfield inserts the governed evaluation step and
records proposals as first-class.

### D5 — `ComponentMatched` → idempotent find-or-create of the (Release, Faultline) Finding

Decision:

- Governance subscribes to Knowledge's `ComponentMatched` event. On each one it **finds-or-creates** the
  Finding for that (Release, Faultline) (D1). This is the **only birth path** for a Finding — Governance
  creates and owns it (CON-0009), **triggered by, never mutated by**, the Knowledge event (DOM-0026).
- **Idempotent:** if the Finding already exists, the newly-matched component is **absorbed into its
  content** (the D1 component list), never duplicated. Re-scans and event re-delivery converge on one
  Finding (same discipline as Evidence/Knowledge).
- **Every match yields a Finding:** a match means the Release genuinely contains an affected component — a
  real governance concern. Urgency is the Position/priority question (D6/later), not a Finding-existence
  question.
- A new Finding starts at status **Identified with no Enterprise Position yet** (D2). The match is a
  Knowledge Proposal / trigger, not authority (CON-0002); Governance governs it.

ADR basis: CON-0009 (only Governance creates Findings), DOM-0026 (Knowledge events trigger governance
workflows; Governance owns its transitions), DOM-0022 (Finding = one Release + one Faultline), CON-0002
(the match is a proposal, not truth), DOM-0033 (reaction to a completed-fact event). Contract:
EDR-KNOWLEDGE-01 D3/D8 (`ComponentMatched`).

PoC mapping: the PoC's correlation writes `component_vulnerabilities` rows directly into a shared table;
the greenfield replaces that cross-context write with an **event** Governance consumes to create its own
Finding — no shared table (Book III §3.5).

### D6 — `FaultlineEnriched` → auto-raise a Governance Proposal + flag for review (never auto-decide)

Decision:

- Governance subscribes to Knowledge's `FaultlineEnriched` event. On it, it finds the existing Findings that
  reference that Faultline and **re-evaluates by raising a system-generated Governance Proposal** against
  each affected Finding, and **flags the Finding for review**. It **never auto-changes the Enterprise
  Position** (DOM-0026: Knowledge never modifies Governance decisions; DOM-0023: only Governance revises a
  Position).
- The Position changes **only when that proposal is accepted** — by a human, or by an explicit
  **Governance-owned** auto-accept rule (D4). Knowledge triggers; Governance decides.
- **Advisory exception:** purely derived, non-authoritative fields (a priority hint / risk score) **may**
  auto-recompute from enrichment, because they inform attention, not authority. The Enterprise Position
  never auto-moves.

| `FaultlineEnriched` carries | Governance auto-action |
| --- | --- |
| Severity ↑ / now KEV-listed | Proposal: escalate / re-prioritize + flag for review |
| Upstream fix now available | Proposal: Mitigated |
| CVE withdrawn/rejected (Faultline Superseded) | Proposal: Not Affected / close Finding |
| Minor field change, no decision impact | Recompute advisory priority only; no proposal |

ADR basis: DOM-0026 (Knowledge triggers workflows, never modifies Governance decisions), DOM-0023 (only
Governance revises a Position), DOM-0024 (proposal before position), CON-0008 (enrichment propagates — but
as a proposal), DOM-0033 (reaction to a completed-fact event). Contract: EDR-KNOWLEDGE-01 D8
(`FaultlineEnriched`).

PoC mapping: the PoC's re-enrichment (`usecase/enrichment/reenrich_signals.go`) updates `risk_context`
signals (EPSS/KEV/exploit) and recomputes `risk_score` in place. The greenfield keeps advisory recompute
but routes any **decision** impact through a Governance Proposal instead of silently changing state.

### D7 — The Finding has an explicit Book II §7.5 lifecycle with a governed reopen path (not forward-only)

Decision:

- The Finding has an explicit lifecycle using Book II §7.5's stages: **Identified → Under Investigation →
  Position Established → Monitoring → Resolved → Archived.**
- Every transition is a **domain business operation emitting an event** (DOM-0030); no direct state edits;
  auditable and reproducible.
- **Not forward-only** (unlike the Faultline ladder, EDR-KNOWLEDGE-01 D7): a **governed reopen path**
  (Monitoring/Resolved → Under Investigation) is taken when new knowledge raises a proposal (D6).
  **Archived is terminal** (release retired).
- Stage meanings: **Identified** — created from a match (D5), no Position yet; **Under Investigation** —
  proposals in flight / flagged for review (D6); **Position Established** — a first Enterprise Position has
  been accepted (D3/D4); **Monitoring** — position set, watching for change; **Resolved** — concern closed
  (fixed / mitigated / not-affected), reopenable; **Archived** — terminal.
- **Two lifecycles, loosely coupled** (D2): the Finding lifecycle tracks the *investigation*; the Position
  versions track the *decision*. A new Position revision does not reset the Finding's stage.

ADR basis: DOM-0030 (explicit lifecycle; transitions via business operations; auditable/reproducible;
names Findings as a target), CON-0003 (explainable history), DOM-0033 (each transition a completed-fact
event). Book II §7.5 supplies the stage names.

Honesty flag: DOM-0030's explicit governed lifecycle is ADR-stated; the six stage names are Book II §7.5's
list. The **reopen path** (vs the Faultline's forward-only ladder) is the engineering choice reflecting that
releases are legitimately re-assessed.

PoC mapping: the PoC has no explicit Finding-lifecycle object — `effective_state` conflates investigation
and decision, and `triage_history` logs decisions. The greenfield adds the explicit investigation
lifecycle as a first-class governed object.

### D8 — Governance publishes thin completed-fact events; Communication consumes Enterprise Positions only

Decision:

- Governance publishes completed-fact events (DOM-0033) via the **shared transactional outbox** (M5;
  mirrors Evidence D7 / Knowledge D8), with **thin payloads + a read API** for detail (BCK-0047).
- **`PositionEstablished` / `PositionRevised`** — the **only** events Communication consumes. Thin payload
  (Finding ID, Release, Faultline/CVE, Position version, stance); Communication fetches the full Position
  via Governance's read API.
- **Finding-lifecycle events** (`FindingOpened` / `FindingResolved` / `FindingReopened` / `FindingArchived`)
  and **proposal events** (`ProposalRaised` / `ProposalAccepted` / `ProposalRejected`) — **Governance-
  internal** (metrics, audit, workflow); **not** consumed by Communication.
- Communication subscribes to **Position events only** (DOM-0025); it never reads Findings or Proposals as
  truth, and may re-present but never reinterpret.
- **VEX generation moves to Communication** (DOM-0025): Governance establishes the Position; Communication
  **materializes** it into VEX / advisories / notifications. Governance never emits VEX. (Shift from the
  PoC's `TriageVEXGenerator` / `themis_generated` VEX.)
- Inbound VEX is separate: vendor VEX enters as a Knowledge **applicability** Proposal (EDR-KNOWLEDGE-01
  D6); D6 here lets it raise a Governance Proposal to decide Not-Affected.

ADR basis: DOM-0025 (Communication consumes only Enterprise Positions; never Findings/Proposals;
materializes into VEX/advisories), DOM-0033 (completed-fact events, published after persist), BCK-0041
(transactional outbox), BCK-0047 (thin events + read API), CON-0009 (Governance authority). Mirrors
Evidence D6 and Knowledge D8.

PoC mapping: the PoC generates VEX in-context (`usecase/vexgen`, `TriageVEXGenerator`); the greenfield
relocates VEX materialization to Communication and has Governance emit Position events instead.

### D9 — The Finding is the aggregate root (append-only Proposals + Position versions + lifecycle), optimistic concurrency

Decision:

- The Finding is **one aggregate and one consistency boundary** (DOM-0031): identity + Faultline reference +
  matched components (D1) + investigation lifecycle (D7) + **append-only Governance Proposals** (D4) +
  **append-only Enterprise Position versions** (D3) + a materialized "current position" pointer. Loaded and
  saved as a single unit through an aggregate-root repository (BCK-0042).
- Proposals and Position versions are **append-only, never overwritten** (D3/D4; CON-0008/CON-0003 preserve
  history). The "current position" is materialized (the latest accepted version), recomputed **inside the
  same transaction** when a proposal is accepted — not computed on read.
- **Optimistic concurrency** (BCK-0043): a version stamp on the Finding. Concurrent touches (a new
  `ComponentMatched` adding a component; a `FaultlineEnriched` raising a proposal; a human accepting a
  proposal) each **load → mutate → save**; the first save wins, the rest hit a version conflict and retry.
  Additive changes + idempotent find-or-create (D5) make retries **converge** — no lost updates, no locks.
- Accept-proposal → establish new Position version → advance Finding stage all happen **in one transaction**
  on the one aggregate, so the decision and its audit trail can never drift apart.
- **Scale:** the aggregate stays **per-Finding**. A `FaultlineEnriched` fan-out across many Findings (same
  CVE, many Releases) is **many small transactions** (one per aggregate), coordinated by a worker (D11) —
  never one giant transaction.

ADR basis: DOM-0031 (aggregate = consistency boundary), BCK-0042 (aggregate-root repository), BCK-0043
(optimistic concurrency), CON-0008 (append-only history), CON-0003 (explainability), DOM-0030 (lifecycle on
the aggregate). Same persistence shape as Evidence D7/D8 and Knowledge D9.

PoC contrast: the PoC spreads Governance state across `risk_context` (mutable, per artifact/component/CVE) +
`triage_history` (append) + generated VEX; the greenfield consolidates into **one Finding aggregate per
(Release, Faultline)** with append-only children.

### D10 — Read side: direct `GetFinding` / `GetPosition` on the aggregate + disposable projections for rollups

Decision:

- **Direct read API on the aggregate store:**
  - **`GetFinding`** (by Finding ID or by (Release, Faultline)) → the Finding with its current Enterprise
    Position + full Position history + the Governance Proposals (accepted and rejected) — full
    explainability (CON-0003).
  - **`GetPosition`** (by Finding, latest or a specific version) → the thin fetch Communication does after a
    Position event (D8).
- **Heavier rollups via disposable, event-built projections** (BCK-0047), never scanning aggregates:
  - **Release security posture** — all Findings + current Positions for Release R (the primary
    customer-facing view).
  - **Faultline blast radius** — which Releases are affected by Faultline F (the Governance-side mirror of
    the projection Knowledge deliberately does not own — EDR-KNOWLEDGE-01 D3/D10).
  - Filters by stance / severity / lifecycle stage.
- Projections never mutate aggregates, are eventually consistent, and are rebuildable from Governance's own
  events (`PositionEstablished`, `FindingOpened`, …). Only heavy rollups get a projection; by-ID/by-key
  reads hit the aggregate store.

ADR basis: BCK-0047 (read models independent, event-built, disposable, eventually consistent; aggregates
authoritative), CON-0003 (explainable reads). Mirrors Evidence D8 / Knowledge D10.

PoC mapping: the PoC queries `risk_context` directly (indexes on `effective_state`, EPSS/KEV) for
dashboards; the greenfield serves single-Finding reads from the aggregate and rollups from projections,
with the affected-Releases rollup now on the Governance side.

### D11 — Governance app surface: AI/feeds propose, authorized humans decide, policy rules as governed auto-accept

Decision:

- **Application services** (BCK-0038; orchestrate domain lifecycle operations, never edit state directly —
  DOM-0030):
  - `OpenOrUpdateFinding` — internal, from `ComponentMatched` (D5).
  - `RaiseProposal` — records a Governance Proposal (D4). **The single entry for all proposers:** human
    triage, the auto-proposal from `FaultlineEnriched` (D6), and AI.
  - `AcceptProposal` / `RejectProposal` — the governed decision; accepting establishes a new Position
    version and advances the lifecycle, in one transaction (D9).
  - Lifecycle ops `ResolveFinding` / `ReopenFinding` / `ArchiveFinding` (D7); the reads (D10).
- **Authority line:**
  - **AI / automation / feeds** — may `RaiseProposal` **only**; never Accept (DOM-0024: AI enabled without
    decision authority).
  - **Human analyst (the risk owner)** — `RaiseProposal` and, when authorized, `AcceptProposal` /
    `RejectProposal`; the human **knowingly owns the accepted risk**. Actor always recorded (CON-0003).
  - **Policy rules** — a **Governance-owned** auto-accept policy may accept certain proposals (e.g. CVE
    withdrawn upstream → auto-accept Not-Affected). The **policy** is the authority, not the proposer
    (DOM-0024 / CON-0009).
- **Propose and accept are recorded as distinct steps** (audit), even when one authorized analyst does both.
- Deferred: the authorization mechanism (roles / RBAC — the PoC uses `api_keys` + `scopes`) is an
  app/adapter concern finalized at implementation. The **rule** — only an authorized governance human or a
  Governance-owned policy may accept/reject — is ADR-fixed here.

ADR basis: DOM-0024 (propose → evaluate → accept/reject; AI without decision authority), CON-0009 (only
Governance establishes authority), BCK-0038 (app services orchestrate domain operations), DOM-0030
(lifecycle operations, not direct edits), CON-0003 (actor recorded), Book II §10.5 (proposal sources).

PoC mapping: the PoC's L4 triage API (`usecase/triage/service.go`, `TriageDecision*`) submits a decision
that is applied **directly**; the greenfield splits it into `RaiseProposal` + `AcceptProposal` with the
human as authority, and adds policy-based auto-accept.

### D12 — Workers + non-owning coordinator; state-based recovery; human-waits held as durable state

Decision:

- **Workers** (BCK-0045, each modifies only Governance aggregates):
  - a **Finding worker** reacting to `ComponentMatched` (D5) + `FaultlineEnriched` (D6) — find-or-create
    Findings, raise proposals;
  - the **outbox relay** publishing Position/lifecycle events (D8);
  - a **projection builder** (D10);
  - an **expiry/timer worker** — accepted-risk-until expiry (the PoC's `ListExpiredAcceptedRiskFindings`) →
    raise a reopen/reconsider proposal.
- A **coordinator** (BCK-0044) sequences the long-running flow (match → open Finding → await decision →
  publish Position) by calling **app services only**; it waits for events (including a human decision) and
  resumes; it never mutates aggregates or enforces rules.
- **Recovery is state-based** (BCK-0050): **(1) idempotent re-run** — inbound events stay queued until
  acknowledged; each step checks persisted state (Finding exists? proposal raised at this Faultline
  version? Position published?); dedup + optimistic concurrency (D9) + exactly-once outbox (D8) converge.
  **(2) an explicit first-class reconciler** — a periodic job inspecting authoritative state
  (matches-expected vs Findings; Findings stuck "flagged for review"; expired accepted-risk; Positions
  established-but-not-published) and continuing incomplete work. **No workflow-replay.**
- **Human-wait is durable state:** a Finding awaiting a human is persisted (Under Investigation / flagged
  for review); a restart re-reads it — a pending decision is never lost and never auto-decided.

ADR basis: BCK-0044 (coordinator sequences/waits/resumes, does not own), BCK-0045 (workers own only their
context), BCK-0050 (state-based recovery from persisted state; reconciliation first-class; replay
rejected). Idempotency mechanics from D8/D9.

PoC mapping: the PoC's expiry sweep (`ListExpiredAcceptedRiskFindings`) and re-enrichment worker exist
already; the greenfield routes their effects through **proposals** and adds the first-class reconciler.

### D13 — Context-first three-ring layout mirroring the Evidence/Knowledge template

Decision:

- Governance is a self-contained tree **`internal/governance/{domain,app,adapters}`** in the same Go
  module; dependencies inward-only; **no cross-context imports** — collaboration solely via events + read
  APIs (D5/D6/D8/D10); enforced by `go-cleanarch` + an architecture test.
- **`domain/`** (pure, depends on nothing): the Finding aggregate (identity, Faultline reference, matched
  components, investigation lifecycle, append-only Governance Proposals, append-only Enterprise Position
  versions, materialized current position, invariants); the Governance Proposal + lifecycle; the Enterprise
  Position value object + extensible value set; Governance events; policy-rule evaluation (pure).
- **`app/`**: use cases (`OpenOrUpdateFinding`, `RaiseProposal`, `Accept/RejectProposal`,
  `Resolve/Reopen/ArchiveFinding`, `GetFinding/GetPosition`, `Reconcile`); ports for the Knowledge event
  subscription, outbox, aggregate repository, projection store, policy rules, authorization.
- **`adapters/`**: inbound event consumers (Knowledge `ComponentMatched` / `FaultlineEnriched`), store
  (Postgres aggregate + outbox + projections), http (triage + read API), workers, policy-rule engine.
- **Own database/schema — no shared tables** with Evidence or Knowledge (Book III §3.5). Same Go module,
  new top-level context folder.

ADR basis: BCK-0037 (source mirrors bounded contexts), Book III §3.2 (context-first, not
technical-layer-first), BCK-0038/0039 (inward-only; domain depends on nothing), Book III §3.5 (events +
read APIs, no shared tables). Same template as Evidence D9 / Knowledge D12.

PoC contrast: the PoC is technical-layer-first (`domain` / `usecase` / `adapter` at the top, shared across
everything); the greenfield is context-first with Governance isolated behind events + read APIs.

## Traceability → issues

One issue per implementable decision; each cross-references its decision + ADR. Suggested delivery: an
OpenSpec change `openspec/changes/phase3-governance/` with these as `tasks.md` groups (mirroring
`phase3-evidence`).

| # | Issue | Realizes |
| --- | --- | --- |
| GOV-01 | Scaffold `internal/governance/{domain,app,adapters}`; wire `go-cleanarch` + architecture test (inward-only, no cross-context imports) | D13 · BCK-0037 |
| GOV-02 | `domain`: Finding aggregate — own identity, (Release, Faultline) business key, matched-components content, investigation lifecycle + invariants (+ tests) | D1·D7·D9 · DOM-0022/0030/0031 |
| GOV-03 | `domain`: Enterprise Position value object — append-only immutable versions, extensible stance set, rationale/actor/inputs (+ tests) | D3 · DOM-0023 |
| GOV-04 | `domain`: Governance Proposal + lifecycle (Proposed → Evaluated → Accepted/Rejected); accept → new Position version (+ tests) | D4 · DOM-0024 |
| GOV-05 | `domain`: Governance events (Finding Opened/Resolved/Reopened/Archived, Proposal Raised/Accepted/Rejected, Position Established/Revised) as completed facts | D8 · DOM-0033 |
| GOV-06 | `app`+`adapters`: consume Knowledge `ComponentMatched` → idempotent find-or-create Finding (every match → a Finding) | D5 · CON-0009/DOM-0026 |
| GOV-07 | `app`+`adapters`: consume Knowledge `FaultlineEnriched` → auto-raise Governance Proposal + flag for review (never auto-decide); advisory priority recompute | D6 · DOM-0026 |
| GOV-08 | `app`: RaiseProposal / Accept / Reject + Finding lifecycle ops; authority line (AI propose-only, human decides, Governance-owned policy auto-accept); optimistic concurrency (+ concurrent-decision test) | D4·D9·D11 · DOM-0024/BCK-0043 |
| GOV-09 | `adapters/store`: Postgres Finding aggregate (append-only Proposals + Position versions + lifecycle + version stamp) + outbox + projections; aggregate-root load/store | D9 · BCK-0042 |
| GOV-10 | `app`: read side — `GetFinding` (position + history + proposals) / `GetPosition` from aggregate; disposable projections (release posture, Faultline blast-radius, filters) | D10 · BCK-0047 |
| GOV-11 | Outbox relay + thin Position events for Communication (`PositionEstablished`/`PositionRevised`); Communication consumes Positions only | D8 · BCK-0041/DOM-0025 |
| GOV-12 | Workers (Finding, expiry/timer) + non-owning coordinator; state-based recovery (idempotent re-run + first-class reconciler, no replay) (+ crash/resume tests) | D11·D12 · BCK-0044/0045/0050 |
| GOV-13 | `adapters/http`: triage + read API — raise/accept/reject proposal, finding/position reads, release posture; error-UX envelope + authorization hook | D10·D11 · BCK-0048 |

## Glossary (this context)

- **Finding** — Governance's release-scoped record of how one Faultline affects one Release; own identity,
  keyed by (Release, Faultline); references the global Faultline, never owns knowledge.
- **Enterprise Position** — the authoritative, committed enterprise decision about a Finding; append-only
  immutable versions; only Governance establishes or revises it.
- **Governance Proposal** — a proposed decision about a Finding (from a human, AI, policy, or knowledge
  evolution); evaluated → accepted/rejected; an accepted proposal becomes a new Position version. Distinct
  from a **Knowledge Proposal** (a source's claim about a CVE — EDR-KNOWLEDGE-01).
- **Stance** — the Position's value (Affected / Not Affected / Under Investigation / Mitigated / Accepted
  Risk / Deferred); controlled but extensible (Book II §8.2).
- **Investigation lifecycle** — the Finding's stages (Identified → Under Investigation → Position
  Established → Monitoring → Resolved → Archived); governed, reopenable, Archived terminal.
- **ComponentMatched** — the inbound Knowledge event that opens/updates a Finding (D5).
- **FaultlineEnriched** — the inbound Knowledge event that triggers re-evaluation: auto-raises a proposal
  and flags for review, never auto-decides (D6).
- **PositionEstablished / PositionRevised** — the outbound events Communication consumes (DOM-0025).
- **Policy rule** — a Governance-owned auto-accept rule; the policy is the authority, not the proposer.
- **Release posture** — the projection listing all Findings + current Positions for a Release.
- **Reconciler** — a first-class periodic job that continues incomplete governance work from persisted
  authoritative state (BCK-0050).
