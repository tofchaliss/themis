# Book III --- The Themis Backend Architecture

## Part III --- Execution Model

## Chapter 10 --- Workflow Orchestration

> *"Workflow orchestration coordinates enterprise execution without
> becoming the owner of enterprise truth."*

------------------------------------------------------------------------

## Chapter Objective

After reading this chapter, the reader should understand:

- The purpose of workflow orchestration.
- How orchestration differs from business ownership.
- How long-running workflows span bounded contexts.
- Why orchestration coordinates rather than decides.

------------------------------------------------------------------------

## 10.1 Purpose of Workflow Orchestration

Enterprise security workflows naturally span multiple bounded contexts.

A software bill of materials may trigger evidence registration,
knowledge correlation, governance assessment, and customer
communication.

These activities require coordination.

The purpose of workflow orchestration is to coordinate execution while
preserving the ownership of each participating bounded context.

------------------------------------------------------------------------

## 10.2 Orchestration Is Not Business Logic

Business rules belong to the Domain Layer.

Business ownership belongs to bounded contexts.

Workflow orchestration belongs to the Application Layer.

An orchestrator decides **when** work should continue, not **what** the
business means.

This separation prevents orchestration from becoming an alternative
source of business truth.

------------------------------------------------------------------------

## 10.3 Long-Running Enterprise Workflows

Some business capabilities cannot complete within a single transaction.

Examples include:

- Evidence onboarding
- Knowledge enrichment
- Enterprise governance
- Communication publication

Each step completes independently and publishes authoritative business
events before the next stage begins.

------------------------------------------------------------------------

## 10.4 Event-Driven Coordination

Workflow progression is driven by completed business facts.

A typical enterprise flow is:

``` text
Evidence
    │
    ▼
Knowledge
    │
    ▼
Governance
    │
    ▼
Communication
```

Each bounded context remains autonomous while participating in the
overall enterprise workflow.

------------------------------------------------------------------------

## 10.5 Failure Handling

Workflow failures are expected.

The orchestrator records workflow progress and resumes from the last
completed authoritative state.

Previously completed business operations are never repeated
unnecessarily.

Recovery is deterministic and based upon persisted enterprise state.

------------------------------------------------------------------------

## 10.6 Workflow Visibility

Every workflow should provide sufficient visibility for:

- operational monitoring,
- auditability,
- troubleshooting,
- progress tracking,
- recovery.

Visibility supports operations without changing business ownership.

------------------------------------------------------------------------

## 10.7 Architectural Responsibilities

Workflow orchestration is responsible for:

- sequencing business capabilities,
- coordinating bounded contexts,
- tracking progress,
- handling retries,
- initiating reconciliation when required.

Workflow orchestration is **not** responsible for:

- enforcing business invariants,
- modifying aggregates directly,
- redefining business meaning,
- bypassing bounded-context ownership.

------------------------------------------------------------------------

## Backend Invariant 10 --- Orchestration Coordinates, It Never Owns

Workflow orchestration coordinates enterprise execution while leaving
business ownership, aggregate invariants, and authoritative decisions
within their respective bounded contexts.

------------------------------------------------------------------------

## Implementation Readiness Checklist

| Question | Status |
| --- | --- |
| Workflow purpose defined | ✓ |
| Ownership preserved | ✓ |
| Event-driven progression established | ✓ |
| Recovery approach documented | ✓ |
| Operational visibility identified | ✓ |
| Ready for Background Workers | ✓ |

------------------------------------------------------------------------

## Chapter Summary

Workflow orchestration provides the execution model for long-running
enterprise processes.

By coordinating bounded contexts through authoritative business events
while preserving ownership and recovery, Themis achieves scalable
enterprise workflows without compromising the integrity of the
Enterprise Security Domain.

The next chapter introduces Background Workers and explains how
asynchronous processing supports continuous enterprise operations.
