# Tasks — phase3-governance (Governance: Findings & Enterprise Position)

> Scope: the Governance context per `proposal.md` / `design.md`; all decisions trace to
> `docs/engineering/decisions/EDR-GOVERNANCE-01.md` (D1–D13). Each group ends with the six Themis gates
> (`make check`), extended to `internal/governance/`. Task IDs map to the EDR issue table (GOV-01…13).
> Depends on `phase3-knowledge` (`ComponentMatched` / `FaultlineEnriched`).

## 1. Context scaffold + architecture enforcement (GOV-01 · D13)

- [x] 1.1 Create `internal/governance/{domain,app,adapters}` with a `doc.go` per package stating the ring.
- [x] 1.2 Extend `go-cleanarch` + depguard; architecture test asserting inward-only + no cross-context
  imports. — `governance` added to `boundedContexts` + `GREENFIELD_CONTEXTS`; `governance-{domain-inner,
  app-domain-only,no-cross-context}` depguard rules (deny evidence/knowledge/communication/intelligence).
- [x] 1.3 Gate: build green; clean-architecture check green. — build + arch-test + go-cleanarch + lint green.

## 2. Domain — Finding, Position, Governance Proposal, events (GOV-02, GOV-03, GOV-04, GOV-05 · D1/D3/D4/D7/D8/D9)

- [x] 2.1 `Finding` aggregate: own identity, (Release, Faultline) business key, matched-components content,
  investigation lifecycle + invariants. — `finding.go`: idempotent `AbsorbComponent`, governed Stage machine
  (reopenable; Archived terminal), append-only Proposals + Position versions, optimistic `version`.
- [x] 2.2 `EnterprisePosition` value object: append-only immutable versions, extensible stance set,
  rationale / actor / inputs. — `position.go` + `stance.go` (6 stances, extensible) + `actor.go`.
- [x] 2.3 `GovernanceProposal` + lifecycle (Proposed → Evaluated → Accepted/Rejected); accept → new
  Position version. — `proposal.go` (status resolves once) + `policy.go` (Governance-owned auto-accept, pure).
- [x] 2.4 Governance events (Finding Opened/Resolved/Reopened/Archived, Proposal Raised/Accepted/Rejected,
  Position Established/Revised). — `event.go`; thin payloads; `NewPositionEvent` picks Established (v1) vs
  Revised (v2+).
- [x] 2.5 Unit tests: identity, lifecycle transitions + reopen, immutable Position versions, accept →
  version, event shapes. — 100% coverage + a `rapid` property test for the version/append-only invariants.
- [x] 2.6 Gate: build + unit tests + coverage green; clean-architecture green. — domain 100%; lint + arch green.

## 3. Inbound seam from Knowledge (GOV-06, GOV-07 · D5/D6)

- [x] 3.1 Consume `ComponentMatched` → idempotent find-or-create the (Release, Faultline) Finding (every
  match → a Finding; absorb component if it exists). — `FindingService.OpenOrUpdateFinding` (find-or-create
  by key, idempotent absorb, FindingOpened on create) + `adapters/inbound.Consumer` ACL (decodes Knowledge's
  wire event, no cross-context import) via the non-owning `Coordinator`.
- [x] 3.2 Consume `FaultlineEnriched` → auto-raise a Governance Proposal + flag for review (never
  auto-decide); recompute advisory priority only. — `ReactToEnrichment` (per-Finding fan-out; system
  proposal → Under Investigation; `proposalFor` maps Withdrawn→NotAffected, KEV/high-sev→Affected, else no
  proposal). Superseded handled too (`OnFaultlineSuperseded`).
- [x] 3.3 Integration tests: match → one Finding; re-delivery idempotent; enrich → proposal, not a Position
  change. — app tests (fakes) + inbound consumer tests (real service, JSON wire payloads) + store crash/resume.
- [x] 3.4 Gate: six Themis gates green. — app 100%, inbound 100%.

## 4. Decision app + persistence (GOV-08, GOV-09 · D4/D9/D11)

- [x] 4.1 `app`: `RaiseProposal` / `AcceptProposal` / `RejectProposal` + `Resolve/Reopen/ArchiveFinding`;
  authority line (AI propose-only, human decides, Governance-owned policy auto-accept); optimistic
  concurrency. — `mutate` retry-on-conflict loop; `requireDecider` (human/policy only → `ErrUnauthorized`);
  `raiseAndMaybeAutoAccept` consults `PolicyRule`s (only system proposals eligible).
- [x] 4.2 `adapters/store`: Postgres Finding aggregate (append-only Proposals + Position versions +
  lifecycle + version stamp) + outbox + projections; aggregate-root load/store. — `findings` (+ materialized
  current position) / `finding_components` / `finding_proposals` (decision upsert) / `finding_positions`
  (immutable) / `governance_outbox`; UPDATE-WHERE-version + 23505→ErrConcurrent; `Relay`.
- [x] 4.3 Integration tests: concurrent decision → converge; accept → new Position version + lifecycle
  advance in one transaction; migration up/down. — embedded-Postgres suite (round-trip, optimistic
  concurrency, concurrent-create converge, outbox relay, projections/fan-out, crash-resume, purge, down/up).
- [x] 4.4 Gate: six Themis gates green. — store 80.5% (80% tier).

## 5. Outbound seam + read side (GOV-11, GOV-10, GOV-13 · D8/D10)

- [x] 5.1 Outbox relay + thin `PositionEstablished` / `PositionRevised` events for Communication (Positions
  only). — `store.Relay` delivers the outbox; `NewPositionEvent` emits Established (v1) / Revised (v2+);
  Finding-lifecycle + proposal events stay Governance-internal.
- [x] 5.2 `app`: read side — `GetFinding` (position + history + proposals) / `GetPosition` from aggregate;
  disposable projections (release posture, Faultline blast-radius, filters). — `ReadService` +
  `ProjectionReader` (served from the materialized current-position columns).
- [x] 5.3 `adapters/http`: triage + read API — raise/accept/reject proposal, finding/position reads,
  release posture; error-UX envelope + authorization hook. — spec-first oapi-codegen
  (`api/governance.openapi.yaml`, `make generate-api-governance`) + `wiring`; Problem envelope; the decider
  actor arrives via the request (authorization-hook seam), the ADR-fixed rule enforced in the app. 97.9%.
- [x] 5.4 Gate: six Themis gates green.

## 6. Workers + coordinator + recovery (GOV-12 · D11/D12)

- [x] 6.1 Workers (Finding worker, expiry/timer for accepted-risk → reopen proposal) + non-owning
  coordinator (app services only). — `Coordinator` (OnComponentMatched / OnFaultlineEnriched /
  OnFaultlineSuperseded, owns nothing) + `adapters/inbound.Consumer` (Finding worker's input) + the outbox
  `Relay`. `cmd/governance` runs the API + a relay/reconcile loop + a pre-M5 event-intake endpoint. The
  accepted-risk expiry/timer worker is **deferred** (needs an accepted-risk-until field on the Position).
- [x] 6.2 State-based recovery: idempotent re-run + first-class reconciler (no replay); human-wait held as
  durable state. — `ReconcileService.Reconcile` drains the durable outbox (positions established-but-not-
  published); inbound idempotency (find-or-create + dedup proposals) + the durable Under-Investigation state
  handle the rest.
- [x] 6.3 Crash/resume tests: pending human decision never lost / never auto-decided. —
  `TestCrashResumePendingDecisionSurvives` (store): a fresh Store re-reads the open proposal / Under
  Investigation stage; no Position is ever auto-established.
- [x] 6.4 Gate: six Themis gates green; `markdownlint-cli2` clean. — full `make check` = exit 0.
