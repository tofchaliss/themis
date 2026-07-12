# ADR-INT-0066: Human Governance Remains the Final Authority

Status

Accepted

Category

Governance

Decision

Regardless of the sophistication of intelligence capabilities, the final authority for enterprise decisions shall remain
with the Governance bounded context and its defined governance policies.

Human authority may be delegated through enterprise policy but shall never be implicitly delegated to an intelligence
provider.

Context

Intelligence systems continuously improve and may eventually outperform humans in specific analytical tasks.

Enterprise accountability, however, remains a business responsibility.

Problem Statement

How should human authority coexist with increasingly capable intelligence systems?

Decision

Intelligence recommendations shall always be evaluated according to enterprise governance policies.

Enterprise policy may define:

- automatic acceptance thresholds,
- mandatory human review,
- escalation rules,
- approval workflows.

The intelligence provider itself shall never determine these policies.

Rationale

Separating intelligence from governance preserves accountability while enabling increasing automation.

Alternatives Considered

AI decides enterprise policy.

Rejected.

Mandatory human review for every proposal.

Rejected.

Consequences

Positive

- Enterprise accountability.
- Flexible automation.
- Regulatory compliance.

Negative

- Governance policy management required.

Implementation Impact

Governance workflows evaluate Proposals according to configurable enterprise policies.

Related ADRs

ADR-CON-0009

ADR-DOM-0024

ADR-INT-0056

Confidence

Very High

References

Book IV

Governance Integration
