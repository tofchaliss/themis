# Themis Architecture Constitution

## Chapter 1 – Vision, Philosophy and Guiding Principles

**Version:** 1.0 (Draft)

## 1. Executive Summary

Themis is an open Product Security Intelligence Platform designed to bring order to the growing complexity of software
supply chain security.

Modern software products are built from hundreds or thousands of third-party components. Each release introduces new
component versions while vulnerability disclosures continue to increase. Themis builds a deterministic, auditable and
reusable knowledge foundation by correlating immutable product evidence, authoritative security intelligence and
validated organizational knowledge to produce trusted product security assessments.

Artificial Intelligence is intentionally **not** the source of truth. AI consumes trusted knowledge produced by the
deterministic backend to explain, summarize, recommend and automate approved workflows while preserving organizational
accountability.

## 2. Why "Themis"

Themis is named after the Greek concept of order, governance and established judgment. The platform exists to bring
order to fragmented security evidence by transforming disconnected information into governed enterprise knowledge.

## 3. Problem Statement

Software vendors face rapid release cadences, growing vulnerability disclosures, fragmented security intelligence and
repetitive manual triage. The challenge is not the lack of vulnerability data; it is consistently transforming
fragmented evidence into trusted product security decisions.

## 4. Vision

Become the trusted open platform for Product Security Intelligence by enabling organizations to build reusable
enterprise security knowledge and communicate product security posture with confidence.

## 5. Mission

Continuously correlate authoritative security intelligence with product-specific context and validated organizational
decisions to produce deterministic product security assessments that improve over time.

## 6. Product Philosophy

- Evidence before opinion.
- Knowledge before automation.
- Governance before AI authority.
- Confidence through deterministic and auditable decisions.
- Themis considers the Product Release—not the SBOM or Container Image—to be the primary business object for Product
  Security.
- A Product Release may contain multiple Deployable Units, each contributing to the overall Product Security Posture.

**Guiding Motto:** Capture Once. Validate Once. Reuse Forever.

## 7. Layered Architecture

### 7.1 Layer 0: Product Evidence (SBOM, scanner results, metadata)

  Product Evidence represents information generated from a specific Deployable Unit within a Product Release. It forms
  the immutable evidence used for deterministic product security assessment.
  In Phase 1, Themis supports CycloneDX SBOM as the primary product evidence.
  Future evidence types include:
    - CycloneDX SBOM
    - Container Image Scanner Reports
    - Runtime Evidence
    - Other product-specific evidence
  Product Evidence always belongs to a Deployable Unit.

### 7.2 Layer 1: Authoritative Security Intelligence (NVD, KEV, EPSS, OSV, vendor advisories, VEX)

- NVD
- OSV
- KEV
- EPSS
- Vendor Advisories
- Vendor VEX
    Vendor VEX is treated as authoritative security intelligence rather than product evidence. It is consumed during
    assessment to understand vendor-specific interpretations of vulnerabilities but is never uploaded as evidence for
    the product being assessed.

### 7.3 Layer 2: Enterprise Knowledge (validated decisions, exceptions, false positives, remediation history)
  
### 7.4 Layer 3: Deterministic Assessment Engine

### 7.5 Layer 4: AI Capability Layer

### 7.6 Layered Architecture ![Themis Layered Architecture](../diagrams/chapter-01/layered-architecture.md)

## 8. Product Security Posture

Product Security Posture is the aggregated security state of a Product Release derived from:

- Deployable Unit Assessments
- Product Evidence
- Authoritative Security Intelligence
- Enterprise Knowledge
- Validated Organizational Decisions

It represents the current security understanding of a release at a specific point in time.

### 8.1. Product assessment flow ![Product Assessment Flow](../diagrams/chapter-1/product-Assessment-Flow.md]

## 9. Trust Model

Product security responsibility always remains with the product organization. AI cannot assume legal, contractual or
organizational ownership of security decisions.

Every assessment must be explainable, traceable, auditable and reproducible.

## 10. Human & AI Governance

Enterprise knowledge is created through validated human decisions or approved organizational policies.

AI begins as an advisor. As organizational knowledge matures, governance may authorize AI to automate narrowly defined
assessment categories. Automation is earned through trust and governance.

## 11. Architectural Invariants

1. Product security accountability cannot be delegated to AI.
2. Deterministic assessment precedes AI reasoning.
3. External security intelligence is never modified.
4. Enterprise knowledge is governed and auditable.
5. Every reusable decision has provenance.
6. Every assessment is explainable.
7. Every validated assessment strengthens future assessments.
8. AI augments decision making but does not replace organizational ownership.

## 12. Positioning

Themis is not a vulnerability scanner, SBOM generator or AI chatbot. It is a deterministic Product Security Intelligence
Platform that builds confidence through reusable enterprise knowledge.

Its primary responsibility is to determine and communicate the security posture of Product Releases through
deterministic assessment rather than isolated vulnerability analysis.

## 13. Closing

Themis provides a governed path from evidence to confidence. Every validated assessment enriches organizational
knowledge, enabling safer automation and trustworthy AI assistance while responsibility remains with the product
organization. As additional evidence becomes available throughout the lifecycle of a Product Release, Themis
continuously refines the deterministic assessment while preserving traceability, auditability and organizational
accountability.

Themis does not promise perfect automation.
