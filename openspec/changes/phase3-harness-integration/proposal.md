# Proposal — phase3-harness-integration (EDR-HARNESS-01)

## Why

Themis needs to use governed AI-runtime executions as evidence for Governance decisions without
the runtime becoming a Governance actor and without Themis depending on the runtime's
orchestration. EDR-TRUST-01 deferred the Decision Proposal payload until a second Decision
capability existed; the AI runtime (`themis-ai-runtime/src/harness`) is that capability.

Grounded in `docs/engineering/decisions/EDR-HARNESS-01.md`, which records the Themis side of
decisions grilled and locked in the runtime repository (D-I-1..9, D-C-1..6, D-L-1..3, D-R-1..4).

## What changes

- **Commission (D1–D4)** — a pre-execution authority record on the Finding: domain aggregate
  member, migration `000014`, `POST /findings/{id}/commissions` and
  `…/commissions/{cid}/withdraw`, thin internal events, `commissions[]` on the Finding view.
- **Harness evidence on proposals (D5, D6)** — `RaiseProposalRequest.evidence`
  (`harness-execution/v1`) + `evidence_trust`; Governance validates shape, correspondence to the
  commission (open, method, deployment), the derived trust class, and Business-Verifies the refs;
  the evidence persists immutably with the proposal and is rendered on `ProposalView`.
- **Intake adapter and CLI (D8, D9)** — `internal/governance/adapters/harness` (the runtime's
  read-only record contracts only; five-link production replay; witnessing-constitution table
  with the L8 premise; evidence mapping) and `cmd/themis-intake` (tuple in → evidence view →
  proposal over the authenticated API).
- **Walls** — depguard allow-list on the adapter; `tests/architecture` exactly-one-importer and
  CLI-graph tests.

## Impact

Governance domain/app/store/http, one migration, the API spec (additive), a new adapter and a
new command, lint and architecture rules. No change to Positions, decisions, or Communication.
