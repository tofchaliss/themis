# Design — phase3-knowledge (Knowledge / Faultline bounded context)

## Source of truth

All engineering decisions (rationale + rejected alternatives) live in
**`docs/engineering/decisions/EDR-KNOWLEDGE-01.md` (D1–D12)**. This document states layout, import rules,
persistence, the cross-context seams, and gates only.

## Layout (D12 · ADR-BCK-0037; Book III §3.2)

Context-first, three rings, same Go module, mirroring the Evidence template:

```text
internal/knowledge/
├── domain/     Faultline aggregate (identity, CVE alias, append-only Proposals, materialized enterprise
│               view, lifecycle ladder, invariants); Proposal value object + kinds; the reconciliation /
│               precedence rule (pure); Knowledge events
├── app/        Fold-Proposal/Enrich, Correlate, Watch, Reconcile, GetFaultline + ports (feed clients,
│               Evidence read-API client, outbox, aggregate repository, projection store)
└── adapters/   feed ACLs (nvd/osv/redhat/epsskev/exploitdb/vexfeed), Evidence read-API client, store
                (Postgres aggregate + outbox + projections), http read API, workers
```

## Import rules (ADR-BCK-0037/0038/0039; Book III §3.5)

- `domain/` imports nothing; `app/` imports `domain/`; `adapters/` import `app/` + `domain/`.
- **No cross-context imports.** Knowledge collaborates only via events + read APIs — never by importing
  another context or sharing its database. Enforced by `go-cleanarch` + depguard + an architecture test.

## Persistence (D9)

- One **Faultline aggregate** = identity + append-only Proposals + materialized enterprise view +
  lifecycle; loaded/saved whole via an aggregate-root repository (BCK-0042).
- **Optimistic concurrency** (BCK-0043): a version stamp; concurrent enrichers converge because Proposals
  are additive and the D2 rule is deterministic.
- Events fire on **enterprise-view change** (not per Proposal), via the **shared transactional outbox**
  (BCK-0041 / M5, seeded by Evidence D7). Disposable **projections** for rollups (BCK-0047).

## Cross-context seams

- **In (from Evidence):** react to `EvidenceRegistered(SBOM)`; read the canonical inventory via Evidence's
  `GetInventory` read API — never its tables (Book III §3.5); keep no copy (EDR-EVIDENCE-01 D6/D8).
- **Out (to Governance):** emit `ComponentMatched` (Governance creates a Finding) and `FaultlineEnriched`
  (Governance re-evaluates). Fire on view-change; the match is a Proposal, not truth (EDR-GOVERNANCE-01
  D5/D6).

## Stack

Canonical stack + rationale: **`docs/engineering/STACK.md`** (read before implementing). Knowledge-specific:
**pgx** + **golang-migrate** (Faultline aggregate + outbox + projections), one **feed ACL** per source
(NVD / OSV / Red Hat CSAF / EPSS / KEV / ExploitDB / vexfeed) → common Proposal, **`pgregory.net/rapid`**
property tests for the precedence rule, an **Evidence read-API client**, **OpenTelemetry** + **zap**.

## Quality gates

The six Themis gates (`make check`) — build, unit tests, coverage, dead-code, integration tests,
clean-architecture — extended to `internal/knowledge/`. Markdown passes `markdownlint-cli2`.
