# ADR-DOM-0027: Business Identity Is Stable Throughout the Lifecycle

Status

Accepted

Category

Identity

Decision

Every major business object shall possess a stable, immutable business identity that remains constant throughout its
lifecycle.

Business identity shall not depend upon persistence technology, implementation details, or deployment topology.

Context

Enterprise objects evolve through multiple lifecycle stages.

Names, versions, metadata, ownership, and relationships may change over time.

Identity must remain stable so that historical reasoning, traceability, and cross-context collaboration remain valid.

Problem Statement

How can enterprise objects evolve without losing their identity?

Decision

Every aggregate root shall have a permanent business identifier.

Identity is established once and never reassigned.

Business identity survives:

- updates,
- migrations,
- technology replacement,
- deployment changes.

Rationale

Stable identities enable:

- long-term traceability,
- deterministic references,
- historical reconstruction,
- reliable event processing.

Alternatives Considered

Database-generated identity

Rejected.

Persistence identifiers are implementation concerns.

Natural keys

Rejected.

Business attributes may legitimately change over time.

Consequences

Positive

- Stable references.
- Independent persistence.
- Reliable history.

Negative

- Business identifier management required.

Implementation Impact

Repositories and Events shall reference business identities rather than implementation-specific identifiers.

Related ADRs

ADR-CON-0005

ADR-CON-0006

Confidence

Very High

References

Book II – Aggregate Identity
