# Book III --- The Themis Backend Architecture

## Part III --- Execution Model

## Chapter 8 --- Consistency Boundaries

> *"Enterprise consistency is achieved through clear ownership, explicit
> boundaries, and controlled collaboration---not through shared state."*

------------------------------------------------------------------------

## Chapter Objective

After reading this chapter, the reader should understand:

- Why consistency boundaries are fundamental to the Backend
    Architecture.
- How aggregate and bounded-context boundaries define transactional
    scope.
- Why Themis avoids distributed transactions.
- How eventual consistency preserves autonomy without sacrificing
    enterprise correctness.

------------------------------------------------------------------------

## 8.1 Understanding Consistency

Consistency ensures that every successful business operation leaves the
enterprise in a valid state.

In Themis, consistency is established first within aggregates, then
within bounded contexts, and finally across the enterprise through
controlled collaboration.

Business correctness always takes precedence over technical convenience.

------------------------------------------------------------------------

## 8.2 Aggregate Consistency

An aggregate represents the smallest transactional consistency boundary.

Within an aggregate:

- Business invariants must always hold.
- Changes succeed or fail together.
- Partial updates are never visible.

The aggregate is therefore the first guardian of enterprise integrity.

------------------------------------------------------------------------

## 8.3 Bounded Context Consistency

A bounded context owns multiple aggregates and guarantees the
correctness of its own business capability.

Transactions remain local to the owning bounded context.

No bounded context relies on another context's transaction to complete
its own business operation.

This preserves autonomy and simplifies recovery.

------------------------------------------------------------------------

## 8.4 Cross-Context Consistency

Enterprise workflows frequently span multiple bounded contexts.

For example:

Evidence → Knowledge → Governance → Communication

These workflows are intentionally **eventually consistent**.

Each bounded context completes its own transaction before publishing an
event that allows the next context to continue.

This approach removes the need for distributed transactions while
preserving enterprise correctness.

------------------------------------------------------------------------

## 8.5 Why Distributed Transactions Are Avoided

Distributed transactions tightly couple independently owned business
capabilities.

Such coupling:

- reduces autonomy,
- complicates recovery,
- increases operational risk,
- weakens scalability.

Themis therefore prefers explicit business collaboration through events
and reconciliation.

------------------------------------------------------------------------

## 8.6 Reconciliation

Failures are expected.

When collaboration is interrupted, reconciliation restores enterprise
consistency from authoritative persisted state.

Reconciliation never invents business state.

It verifies completed work, identifies missing progress, and safely
resumes execution according to business rules.

------------------------------------------------------------------------

## 8.7 Designing for Consistency

Every backend capability should answer:

- What is the aggregate boundary?
- What is the transaction boundary?
- Which context owns this state?
- Which event communicates completion?
- How is interrupted work recovered?

These questions define architectural consistency before implementation
begins.

------------------------------------------------------------------------

## Backend Invariant 8 --- Consistency Follows Ownership

Consistency is maintained by the owner of the business capability.

Cross-context collaboration extends enterprise behaviour without
extending transactional ownership.

------------------------------------------------------------------------

## Implementation Readiness Checklist

| Question | Status |
| --- | --- |
| Aggregate consistency defined | ✓ |
| Context consistency defined | ✓ |
| Distributed transactions avoided | ✓ |
| Eventual consistency established | ✓ |
| Recovery through reconciliation introduced | ✓ |
| Ready for Concurrency Management | ✓ |

------------------------------------------------------------------------

## Chapter Summary

Consistency in Themis is achieved through explicit ownership, aggregate
boundaries, local transactions, event-driven collaboration, and
reconciliation.

By avoiding distributed transactions and preserving bounded-context
autonomy, the Backend Architecture maintains enterprise integrity while
remaining scalable, resilient, and faithful to the Enterprise Security
Domain.

The next chapter examines Concurrency and Race Condition Management,
explaining how Themis prevents conflicting execution without
compromising business correctness.
