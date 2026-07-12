# ADR-BCK-0053: Configuration Shall Not Contain Business Behaviour

Status

Accepted

Category

Configuration

Decision

Configuration shall control operational characteristics of the Backend but shall never define enterprise business rules
or business semantics.

Business behaviour belongs exclusively to the Domain.

Context

Enterprise applications require configuration for deployment, infrastructure, performance, security, and integration.

Over time, business behaviour is often moved into configuration files for convenience.

Problem Statement

How should configuration be separated from business behaviour?

Decision

Configuration may define:

- endpoints,
- credentials,
- timeouts,
- feature enablement,
- deployment settings,
- infrastructure parameters.

Configuration shall never define:

- aggregate invariants,
- governance rules,
- enterprise truth,
- business ownership.

Business behaviour remains part of the Domain Model.

Rationale

Separating configuration from business behaviour preserves architectural consistency and prevents operational
environments from redefining enterprise semantics.

Alternatives Considered

Configuration-Driven Business Logic

Rejected.

Business semantics should not vary by deployment environment.

Consequences

Positive

- Stable Domain.
- Predictable behaviour.
- Easier testing.

Negative

- Some operational flexibility intentionally restricted.

Implementation Impact

Configuration frameworks shall remain outside the Domain Layer.

Related ADRs

ADR-CON-0005

ADR-BCK-0039

Confidence

Very High

References

Book III

Backend Design Principles
