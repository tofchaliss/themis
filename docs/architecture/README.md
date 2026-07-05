# Architecture Decision Records (ADRs)

Durable architecture decisions for Themis — one Markdown file per decision, numbered
sequentially: `NNNN-<kebab-title>.md` (e.g. `0001-ai-enrichment-over-postgres-seam.md`).

An ADR records a single decision: its context, the choice made, the alternatives weighed, and
the consequences. ADRs are immutable once accepted — a decision that changes gets a **new** ADR
that supersedes the old one (note the supersession in both).

## When to add one

Graduate a decision into an ADR here when it is cross-cutting and durable — it outlives the change
that produced it. In-flight design discussion and per-decision logs live in
[`../current-changes/`](../current-changes/) (e.g. `phase-2b-grilling.md`); a per-change
proposal / design / tasks set lives under [`../../openspec/changes/`](../../openspec/changes/).

## Related

- Original proposal's 9 ADRs (historical): [`../archive/proposal-initial.md`](../archive/proposal-initial.md)
- Project architecture reference: [`../current-changes/PROJECT_CONTEXT.md`](../current-changes/PROJECT_CONTEXT.md)
