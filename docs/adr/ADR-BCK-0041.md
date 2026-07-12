# ADR-BCK-0041: Business Events Shall Be Published Only After Successful Persistence

Status

Accepted

Category

Event Architecture

Decision

Business Events shall be published only after the successful persistence of authoritative business state.

No event shall be published for a business operation that has not been durably committed.

Context

Events are the primary collaboration mechanism between bounded contexts.

Publishing an event before persistence risks consumers acting upon business facts that may later be rolled back.

Problem Statement

When should business events be published?

Decision

The publication sequence shall always be:

Business Operation

↓

Aggregate Validation

↓

Persistence Commit

↓

Business Event Publication

↓

Cross-Context Consumption

If persistence fails, no Business Event shall be emitted.

Rationale

This guarantees that every published event represents a completed business fact.

Alternatives Considered

Publish Before Commit

Rejected.

Consumers could observe non-existent business state.

Eventually Correct Failed Events

Rejected.

Business truth must never depend upon later compensation.

Consequences

Positive

- Reliable collaboration.
- Consistent event history.
- Simplified recovery.

Negative

- Event publication depends upon successful persistence.

Implementation Impact

Application Services shall publish events only after repositories confirm successful persistence.

Related ADRs

ADR-CON-0012

ADR-DOM-0033

ADR-BCK-0040

Confidence

Very High

References

Book III

Event Architecture
