# ADR-CON-0002: Proposal Before Truth

Status

Accepted

Category

Governance

Decision

No information originating from external systems, artificial intelligence, automated reasoning, human analysis, or
internal processing shall become authoritative enterprise truth immediately.

Every non-authoritative input shall first exist as a Proposal and shall become enterprise truth only after validation by
the authoritative owner of the corresponding business capability.

Context

Enterprise security information originates from numerous independent sources.

Examples include:

- Software Bills of Materials (SBOMs)
- Vulnerability databases
- Vendor advisories
- Security scanners
- Threat intelligence feeds
- Artificial Intelligence
- Human analysts
- Customer feedback

Each source has different confidence levels, update frequencies, completeness, and authority.

Treating every incoming observation as enterprise truth would result in conflicting conclusions, duplicated findings,
incorrect customer communication, and unstable enterprise reasoning.

The architecture therefore requires an explicit transition between observed information and authoritative enterprise
truth.

Problem Statement

How can the enterprise continuously consume information from many independent sources while ensuring that authoritative
business decisions remain deterministic, explainable, and governed?

Decision

The architecture introduces the concept of Proposal Before Truth.

Every incoming observation, recommendation, enrichment, correction, or analysis shall initially exist only as a
Proposal.

A Proposal represents information that has not yet become authoritative.

Only the authoritative owner of the corresponding business capability may evaluate that Proposal and determine whether
it becomes enterprise truth.

No component may bypass this process.

This rule applies equally to:

- External feeds
- Artificial Intelligence
- Human operators
- Internal automation
- Future processing capabilities

Truth is therefore not discovered automatically.

Truth is established through governed acceptance.

Rationale

Separating proposals from truth creates a stable enterprise reasoning model.

It allows:

- Multiple opinions to coexist.
- AI recommendations without AI authority.
- Vendor opinions without vendor ownership.
- Human review where necessary.
- Continuous enrichment without destabilizing enterprise state.

The enterprise therefore evolves through controlled governance rather than uncontrolled information updates.

Alternatives Considered

1. Immediate Acceptance

   Rejected.

   Automatically accepting incoming information allows incorrect, incomplete, or conflicting observations to become
   enterprise truth.

2. Source Trust Model

   Rejected.

   Even highly trusted sources may disagree with enterprise-specific business context.

   Authority belongs to the enterprise rather than the information source.

3. Human Approval for Everything

   Rejected.

   Not every proposal requires manual review.

   Authoritative owners may apply deterministic business rules, automated governance, or future policy engines where
   appropriate.

Consequences

Positive

- Stable enterprise reasoning.
- Explainable decision making.
- AI remains advisory rather than authoritative.
- Vendor recommendations remain reference information.
- Enterprise-specific business context is preserved.
- Future automation can evolve safely.

Negative

- Additional proposal lifecycle must be managed.
- Governance introduces additional processing before enterprise truth changes.
- Proposal history requires persistence and auditability.

Implementation Impact

This decision governs:

- Knowledge enrichment.
- Governance workflows.
- Enterprise Position establishment.
- AI proposal processing.
- Human review.
- Workflow orchestration.
- Background processing.
- Future policy engines.

Every implementation shall distinguish between proposals and authoritative state.

Related ADRs

ADR-CON-0001
Single Authoritative Ownership

Confidence

Very High

This principle has been repeatedly validated throughout the architecture and forms the foundation of enterprise
governance, AI integration, and future decision automation.

References

Book I — Constitution

- Proposal Model
- Enterprise Truth

Book II — Enterprise Security Domain

- Governance
- Findings
- Enterprise Position

Book III — Backend Architecture

- Workflow Orchestration
- Event Architecture
- Background Workers
