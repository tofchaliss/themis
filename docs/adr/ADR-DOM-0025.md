# ADR-DOM-0025: Communication Consumes Enterprise Positions Only

Status

Accepted

Category

Communication

Decision

The Communication bounded context shall consume only authoritative Enterprise Positions.

Communication shall never publish Evidence, Knowledge, Findings, or Proposals as enterprise truth.

Context

Customers require consistent, authoritative communication.

Intermediate business objects represent enterprise reasoning rather than enterprise commitments.

Problem Statement

Which business object should Communication publish?

Decision

Communication consumes Enterprise Positions exclusively.

Communication may transform presentation for different audiences, but it shall never reinterpret enterprise decisions.

Rationale

Separating governance from publication ensures consistent enterprise messaging.

Alternatives Considered

Communication publishes Findings

Rejected.

Findings are internal governance artifacts.

Communication publishes Proposals

Rejected.

Proposals are not enterprise truth.

Consequences

Positive

- Consistent messaging.
- Stable publication model.
- Independent communication evolution.

Negative

- Communication depends upon Governance completion.

Implementation Impact

Communication APIs, reports, advisories, and customer notifications shall originate from Enterprise Positions.

Related ADRs

ADR-CON-0010

ADR-DOM-0023

Confidence

Very High

References

Book II – Communication
