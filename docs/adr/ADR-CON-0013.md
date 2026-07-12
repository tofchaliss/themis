# ADR-CON-0013: Enterprise Consistency Through Local Transactions

Status

Accepted

Category

Consistency

Decision

Enterprise consistency shall be achieved through local transactional consistency within bounded contexts and coordinated
collaboration across bounded contexts.

The architecture shall avoid distributed transactions as a mechanism for enterprise consistency.

Context

Enterprise workflows frequently span multiple business capabilities.

Attempting to execute these workflows as a single distributed transaction introduces tight coupling, operational
complexity, and reduced resilience.

The architecture requires a consistency model that preserves ownership while allowing independent evolution.

Problem Statement

How can enterprise correctness be maintained across multiple bounded contexts without sacrificing scalability or
architectural independence?

Decision

Each bounded context shall own its own transactional consistency.

Cross-context consistency shall be achieved through:

- authoritative events,
- workflow orchestration,
- reconciliation,
- deterministic business processing.

Distributed transactions shall not be used to establish enterprise correctness.

Rationale

Local consistency provides:

- simpler recovery,
- independent evolution,
- clearer ownership,
- improved scalability,
- reduced operational complexity.

Enterprise correctness emerges through collaboration rather than shared transactions.

Alternatives Considered

1. Distributed Transactions

   Rejected.

   They tightly couple independent business capabilities and reduce resilience.

2. Global Transaction Manager

   Rejected.

   A central transaction manager becomes a bottleneck and weakens bounded-context autonomy.

3. Shared Persistence

   Rejected.

   Shared persistence violates Single Authoritative Ownership.

Consequences

Positive

- Independent bounded contexts.
- Improved scalability.
- Better fault isolation.
- Simpler operational recovery.

Negative

- Eventual consistency must be accepted.
- Reconciliation becomes an architectural capability.

Implementation Impact

Application Services, Workflow Orchestration, Event Architecture, and Background Workers shall implement this
consistency model.

Related ADRs

ADR-CON-0001

ADR-CON-0011

ADR-CON-0012

Confidence

Very High

References

Book III – Consistency Boundaries

Book III – Workflow Orchestration

Book III – Concurrency and Race Condition Management
