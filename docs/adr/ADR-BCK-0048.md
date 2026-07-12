# ADR-BCK-0048: Backend APIs Expose Use Cases Rather Than Persistence

Status

Accepted

Category

API

Decision

Backend APIs shall expose enterprise use cases.

APIs shall never expose repositories, persistence structures, database schemas, or aggregate internals directly.

Context

Backend APIs represent the implementation boundary between external consumers and enterprise business capabilities.

Problem Statement

What should Backend APIs represent?

Decision

Every API shall correspond to an Application Service use case.

APIs invoke business behaviour.

They do not expose CRUD operations by default.

Repository implementation remains internal.

Rationale

Use-case APIs preserve:

- business intent,
- implementation independence,
- architectural stability.

Alternatives Considered

CRUD APIs

Rejected.

CRUD does not represent enterprise behaviour.

Database APIs

Rejected.

Persistence is not an architectural boundary.

Consequences

Positive

- Rich APIs.
- Better encapsulation.
- Stable evolution.

Negative

- Additional API design effort.

Implementation Impact

REST, gRPC, GraphQL, or future interfaces shall expose business capabilities rather than persistence operations.

Related ADRs

ADR-BCK-0038

ADR-BCK-0042

Confidence

Very High

References

Book III

Application Layer
