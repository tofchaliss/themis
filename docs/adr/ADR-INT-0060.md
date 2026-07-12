# ADR-INT-0060: Prompt Construction Is Infrastructure

Status

Accepted

Category

Prompt Engineering

Decision

Prompt construction shall be treated as an infrastructure concern rather than a business concern.

Business capabilities shall supply structured Domain objects.

Prompt generation remains the responsibility of the Intelligence Gateway.

Context

Prompt engineering evolves rapidly.

Embedding prompts inside business logic tightly couples enterprise behaviour to specific intelligence providers.

Problem Statement

Where should prompt engineering reside?

Decision

Prompt construction shall occur entirely within the Intelligence Infrastructure.

Application Services provide:

- Domain objects
- Business context
- Capability name

The Intelligence Gateway transforms these into provider-specific prompts.

Rationale

Separating prompts from business logic preserves:

- provider independence
- maintainability
- architectural clarity
- easier experimentation

Alternatives Considered

Prompt generation inside Application Services.

Rejected.

Prompt generation inside Domain objects.

Rejected.

Consequences

Positive

- Cleaner architecture.
- Easier prompt iteration.
- Technology independence.

Negative

- Additional infrastructure layer.

Implementation Impact

Business code shall never contain provider-specific prompts.

Related ADRs

ADR-CON-0005

ADR-BCK-0036

ADR-INT-0058

ADR-INT-0059

Confidence

Very High

References

Book IV

Prompt Construction
