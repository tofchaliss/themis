# ADR-BCK-0047: Read Models Are Independent of Aggregate Persistence

Status

Accepted

Category

Read Model

Decision

Read Models shall exist independently of Aggregate persistence.

Read Models optimize information retrieval without redefining business ownership.

Context

Enterprise queries frequently span multiple Aggregates and Bounded Contexts.

Optimizing query performance must not compromise Aggregate ownership.

Problem Statement

How should complex enterprise queries be supported?

Decision

Read Models shall be generated from authoritative business events.

Read Models:

- are disposable,
- are eventually consistent,
- do not own business state.

Aggregate Repositories remain authoritative.

Rationale

Separating Read Models from Aggregates preserves:

- aggregate integrity,
- scalable querying,
- simpler persistence.

Alternatives Considered

Query Aggregates Directly

Rejected.

Aggregate models optimize consistency rather than reporting.

Shared Reporting Database

Rejected.

Reporting shall not redefine business ownership.

Consequences

Positive

- Faster queries.
- Independent optimization.
- Better scalability.

Negative

- Eventual consistency accepted.

Implementation Impact

Read projections shall never modify Aggregate state.

Related ADRs

ADR-BCK-0042

ADR-BCK-0046

Confidence

Very High

References

Book III

Repository Strategy
