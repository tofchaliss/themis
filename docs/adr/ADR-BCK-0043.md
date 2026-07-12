# ADR-BCK-0043: Optimistic Concurrency Is the Default Consistency Strategy

Status

Accepted

Category

Concurrency

Decision

Aggregate updates shall use optimistic concurrency by default.

Concurrent modifications shall be detected through Aggregate versioning rather than pessimistic locking.

Context

Enterprise workflows execute concurrently across multiple users and background workers.

Long-lived pessimistic locks reduce scalability and increase operational complexity.

Problem Statement

How should concurrent Aggregate modification be managed?

Decision

Each Aggregate maintains a version.

Updates succeed only when the expected version matches the persisted version.

Version conflicts trigger reconciliation rather than overwrite.

Rationale

Optimistic concurrency aligns with:

- independent bounded contexts,
- event-driven collaboration,
- scalable execution.

Alternatives Considered

Pessimistic Locking

Rejected.

Locks reduce throughput and increase coupling.

Last Writer Wins

Rejected.

Business correctness cannot depend upon execution timing.

Consequences

Positive

- Better scalability.
- Deterministic updates.
- Simpler distributed execution.

Negative

- Conflict handling required.

Implementation Impact

Repositories shall expose version-aware persistence operations.

Related ADRs

ADR-CON-0013

ADR-DOM-0031

Confidence

Very High

References

Book III

Concurrency
