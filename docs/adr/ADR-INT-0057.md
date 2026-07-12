# ADR-INT-0057: Intelligence Produces Structured Proposals

Status

Accepted

Category

Proposal Model

Decision

Every intelligence capability shall produce structured, schema-validated Proposals.

Natural language responses shall never become enterprise inputs directly.

Context

Intelligence systems frequently generate unstructured responses.

Enterprise software requires deterministic processing.

Problem Statement

How can intelligence outputs be consumed safely by enterprise software?

Decision

Every intelligence response shall be transformed into a structured Proposal.

Each Proposal shall contain:

- recommendation
- confidence
- supporting evidence
- reasoning
- originating capability
- execution metadata

Only validated Proposals may enter Governance workflows.

Rationale

Structured Proposals provide:

- deterministic processing
- explainability
- validation
- auditing

Alternatives Considered

Free-form text processing.

Rejected.

Consequences

Positive

- Predictable integration.
- Strong validation.
- Better automation.

Negative

- Additional response parsing.

Implementation Impact

Every capability shall publish typed Proposal objects rather than strings.

Related ADRs

ADR-INT-0056

ADR-CON-0002

Confidence

Very High

References

Book IV

Proposal Processing
