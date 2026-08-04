# Book I --- The Themis Architecture Constitution

## Part II --- The Philosophy

## Chapter 6 --- Proposal Before Truth

> *"Truth is never assumed. It is established through disciplined
> evaluation of proposals."*

## Chapter Objective

After reading this chapter, the reader should understand:

- Why every authoritative state begins as a proposal.
- How the proposal model unifies the entire architecture.
- Why proposal-driven evolution improves governance, explainability,
    and extensibility.
- Why proposals preserve enterprise ownership while enabling
    automation.

------------------------------------------------------------------------

## 6.1 The Nature of Enterprise Change

Enterprise systems are not static. New evidence arrives continuously,
engineering investigations complete, vendors revise guidance, AI models
generate recommendations, and customers request clarification.

Every one of these events has the potential to change the enterprise's
understanding.

The architectural question is therefore not **whether change occurs**,
but **how change is introduced**.

Themis answers this through a single principle:

> Every authoritative change begins as a proposal.

------------------------------------------------------------------------

## 6.2 Why Direct Mutation Fails

Many enterprise platforms allow business state to be updated directly.

A scanner updates a record.

A script changes a status.

An engineer edits a finding.

Over time, the origin of decisions becomes difficult to reconstruct.

Questions such as:

- Who changed this?
- Why was it changed?
- Which evidence supported the change?

become increasingly difficult to answer.

Direct mutation sacrifices explainability for convenience.

Themis intentionally avoids this architectural pattern.

------------------------------------------------------------------------

## 6.3 The Proposal Pipeline

Themis introduces a consistent progression across every bounded context.

``` text
Proposal
      ↓
Evaluation
      ↓
Authoritative State
```

This pattern appears repeatedly:

- Evidence is proposed before it becomes registered enterprise
    evidence.
- Knowledge proposals are evaluated before becoming Enterprise
    Knowledge.
- Governance proposals are evaluated before changing Enterprise
    Position.
- Materialization requests are evaluated before producing
    communication artifacts.

The proposal model is therefore not a workflow.

It is an architectural invariant.

------------------------------------------------------------------------

## 6.4 Proposal Sources Are Interchangeable

The source of a proposal is architecturally insignificant.

A proposal may originate from:

- External integrations
- Security scanners
- Vendor advisories
- AI reasoning
- Human engineers
- Enterprise policy engines
- Future extensions

Every proposal follows the same evaluation model.

This allows Themis to evolve without changing its architectural
principles.

------------------------------------------------------------------------

## 6.5 Explainability Through Proposals

Because every change originates as a proposal, every authoritative state
can explain:

- What changed?
- Why did it change?
- Which proposal initiated the change?
- Which evidence supported the proposal?
- Who accepted it?

Explainability therefore emerges naturally from the proposal model
rather than being added afterwards.

------------------------------------------------------------------------

## 6.6 The Foundation of Extensibility

Proposal-driven evolution also enables long-term extensibility.

New scanners do not require changes to Governance.

New AI models do not bypass Knowledge.

New communication formats do not alter Enterprise Position.

Instead, every new capability contributes proposals while authoritative
ownership remains unchanged.

This separation allows the platform to evolve for years without
compromising architectural consistency.

------------------------------------------------------------------------

## Constitutional Principle 3 --- Proposal Before Truth

Enterprise truth is never created through direct mutation.

Every evolution of authoritative state begins as a proposal that is
evaluated by the capability responsible for that business object.

This principle preserves ownership, explainability, governance, and
extensibility across the entire platform.

------------------------------------------------------------------------

## Chapter Summary

Key observations include:

- Direct mutation weakens enterprise reasoning.
- Every authoritative state begins with a proposal.
- Proposal-driven evolution unifies every bounded context.
- Proposal sources are interchangeable; authoritative ownership is
    not.
- Explainability and extensibility emerge naturally from this model.

The next chapter explores **Explainability as a First-Class Principle**,
showing why enterprise trust depends not only on correct decisions but
also on the ability to justify them.
