# Book III --- The Themis Backend Architecture

## Part II --- Core Architecture

## Chapter 4 --- Application Layer

> *"The Application Layer executes business use cases. It does not own
> business truth."*

------------------------------------------------------------------------

## Chapter Objective

After reading this chapter, the reader should understand:

- The purpose of the Application Layer.
- The distinction between Application Services and Domain Models.
- Why orchestration differs from business ownership.
- How application services collaborate while preserving
    bounded-context independence.

------------------------------------------------------------------------

## 4.1 The Role of the Application Layer

The Backend Architecture is divided into distinct responsibilities.

The Domain defines business meaning.

The Application Layer executes business use cases.

The Persistence Layer preserves state.

The Infrastructure Layer provides technical capabilities.

The Application Layer sits between the Domain and Infrastructure,
coordinating execution without redefining business rules.

------------------------------------------------------------------------

## 4.2 Application Services

Application Services implement business use cases.

Examples include:

- Register Evidence
- Evolve Faultline
- Create Finding
- Establish Enterprise Position
- Publish Communication

Application Services coordinate work but do not contain business rules
that belong to aggregates or domain services.

Business decisions remain within the Domain.

------------------------------------------------------------------------

## 4.3 Orchestration vs. Ownership

A common mistake is to confuse orchestration with ownership.

An Application Service may coordinate multiple activities, but ownership
remains within the bounded context responsible for the underlying
aggregate.

For example:

- An Evidence Application Service may validate and register Evidence.
- It does not perform enterprise knowledge correlation.
- Knowledge evolution belongs exclusively to the Knowledge Context.

Orchestration never transfers ownership.

------------------------------------------------------------------------

## 4.4 Cross-Context Collaboration

Application Services may initiate collaboration across bounded contexts
through published business events or well-defined interfaces.

They shall not:

- modify another context's aggregates,
- bypass ownership,
- invoke another context's repositories directly.

This preserves architectural independence while enabling end-to-end
workflows.

------------------------------------------------------------------------

## 4.5 Transactions

An Application Service defines the transactional boundary for a business
use case within its bounded context.

A transaction should:

- complete one business operation,
- preserve aggregate invariants,
- publish business events only after successful completion.

Long-running workflows spanning multiple contexts are not implemented as
distributed transactions.

------------------------------------------------------------------------

## 4.6 Validation

The Application Layer performs:

- request validation,
- authorization,
- use-case coordination,
- transaction management.

The Domain performs:

- business validation,
- invariant enforcement,
- business decision making.

This separation ensures that business rules remain independent of
delivery mechanisms.

------------------------------------------------------------------------

## 4.7 Failure and Recovery

Failures are expected.

Application Services therefore:

- return deterministic outcomes,
- avoid partial business state,
- rely on retry and reconciliation for cross-context workflows,
- preserve idempotent behavior where applicable.

Recovery begins from the last authoritative state rather than replaying
arbitrary execution paths.

------------------------------------------------------------------------

## Backend Invariant 4 --- Application Services Coordinate but Do Not Own

Application Services execute business use cases.

They coordinate execution, transactions and collaboration while leaving
business ownership and invariant enforcement to the Domain Model and
bounded contexts.

------------------------------------------------------------------------

## Implementation Readiness Checklist

| Question | Status |
| --- | --- |
| Business ownership preserved | ✓ |
| Application responsibilities defined | ✓ |
| Transaction boundaries localized | ✓ |
| Cross-context ownership protected | ✓ |
| Recovery strategy introduced | ✓ |
| Ready for Domain Layer | ✓ |

------------------------------------------------------------------------

## Chapter Summary

The Application Layer provides the execution model for the Backend
Architecture.

It coordinates business use cases, manages transactions, validates
requests and collaborates across bounded contexts while preserving the
ownership, invariants and business meaning established by the Domain.

The next chapter introduces the Domain Layer and explains how
aggregates, domain services and value objects enforce the enterprise
business model during execution.
