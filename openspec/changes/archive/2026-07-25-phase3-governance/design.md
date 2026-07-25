# Design — phase3-governance (Governance: Findings & Enterprise Position)

## Source of truth

All engineering decisions (rationale + rejected alternatives) live in
**`docs/engineering/decisions/EDR-GOVERNANCE-01.md` (D1–D13)**. This document states layout, import rules,
persistence, the cross-context seams, and gates only.

## Layout (D13 · ADR-BCK-0037; Book III §3.2)

Context-first, three rings, same Go module, mirroring the Evidence/Knowledge template:

```text
internal/governance/
├── domain/     Finding aggregate (identity, Faultline reference, matched components, investigation
│               lifecycle, append-only Governance Proposals, append-only Enterprise Position versions,
│               materialized current position, invariants); Governance Proposal + lifecycle; Enterprise
│               Position value object + extensible stance set; policy-rule evaluation (pure); events
├── app/        OpenOrUpdateFinding, RaiseProposal, Accept/RejectProposal, Resolve/Reopen/ArchiveFinding,
│               GetFinding/GetPosition, Reconcile + ports (Knowledge event subscription, outbox, aggregate
│               repository, projection store, policy rules, authorization)
└── adapters/   inbound event consumers (ComponentMatched / FaultlineEnriched), store (Postgres aggregate +
                outbox + projections), http (triage + read API), workers, policy-rule engine
```

## Import rules (ADR-BCK-0037/0038/0039; Book III §3.5)

- `domain/` imports nothing; `app/` imports `domain/`; `adapters/` import `app/` + `domain/`.
- **No cross-context imports.** Governance collaborates only via events + read APIs; it references a
  Faultline by immutable id and never imports Knowledge or shares its DB. Enforced by `go-cleanarch` +
  depguard + an architecture test.

## Persistence (D9)

- The **Finding is the aggregate root** = identity + Faultline ref + matched components + investigation
  lifecycle + append-only Governance Proposals + append-only Position versions + materialized current
  position; loaded/saved whole (BCK-0042).
- **Optimistic concurrency** (BCK-0043): a version stamp; accept-proposal → new Position version → advance
  lifecycle in one transaction. Aggregate stays **per-Finding** (a `FaultlineEnriched` fan-out is many
  small transactions, one per Finding).
- Events on state change via the **shared outbox** (BCK-0041 / M5). Disposable **projections** for rollups
  (BCK-0047).

## Cross-context seams

- **In (from Knowledge):** `ComponentMatched` → idempotent find-or-create the (Release, Faultline) Finding
  (every match → a Finding, starts Identified, no Position). `FaultlineEnriched` → auto-raise a Governance
  Proposal + flag for review; **never auto-decide** (DOM-0026); advisory priority may recompute.
- **Out (to Communication):** thin `PositionEstablished` / `PositionRevised` events (+ read API);
  Communication consumes **Positions only** (DOM-0025). Finding/Proposal events stay internal.

## Authority (D11 · CON-0009/CON-0015/DOM-0024)

`RaiseProposal` is the single proposer entry (human / AI / policy / knowledge-evolution). **AI proposes
only; authorized humans decide; a Governance-owned policy may auto-accept.** Propose and accept are
recorded as distinct steps.

## Stack

Canonical stack + rationale: **`docs/engineering/STACK.md`** (read before implementing).
Governance-specific: **pgx** + **golang-migrate** (Finding aggregate — append-only Proposals + Position
versions + outbox + projections), **chi** + **oapi-codegen** (triage + read API), **Knowledge event
consumers**, **`pgregory.net/rapid`** for lifecycle/version invariants, **OpenTelemetry** + **zap**.

## Quality gates

The six Themis gates (`make check`) — build, unit tests, coverage, dead-code, integration tests,
clean-architecture — extended to `internal/governance/`. Markdown passes `markdownlint-cli2`.
