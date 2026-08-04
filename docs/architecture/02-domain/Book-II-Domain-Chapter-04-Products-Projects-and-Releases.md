# Book II --- The Themis Enterprise Security Domain

## Part II --- The Domain Model

## Chapter 4 --- Products, Projects and Releases

> *"Security decisions are never made in isolation. They are always made
> in the context of a product, a project, and a release."*

## Chapter Objective

After reading this chapter, the reader should understand:

- Why Products, Projects, and Releases form the primary business
    hierarchy within Themis.
- Why the Release is the governance boundary of the domain.
- How ownership flows through the hierarchy.
- Why this hierarchy remains stable regardless of implementation
    technology.

------------------------------------------------------------------------

## 4.1 The Enterprise Product Hierarchy

Every enterprise develops software to deliver business value.

Within Themis, this business reality is represented by a simple but
deliberate hierarchy:

``` text
Product
    └── Project
            └── Release
```

This hierarchy represents business ownership rather than deployment or
implementation.

It provides the context within which enterprise security decisions are
made.

------------------------------------------------------------------------

## 4.2 Product

A Product is the highest business entity managed by the enterprise.

It represents a deliverable that is offered to customers and maintained
throughout its lifecycle.

A Product establishes:

- Business identity
- Product ownership
- Long-term evolution
- Customer commitments

Products may contain one or more Projects.

Products do not directly own security findings.

------------------------------------------------------------------------

## 4.3 Project

A Project is a logical subdivision of a Product.

Projects evolve independently while contributing to the overall Product.

Projects provide organizational and engineering boundaries.

Typical responsibilities include:

- Functional scope
- Engineering ownership
- Build lifecycle
- Component composition

Projects contain one or more Releases.

Projects do not directly own enterprise positions.

------------------------------------------------------------------------

## 4.4 Release

A Release is the primary governance boundary of the Domain.

A Release represents a governed snapshot of one or more Projects
delivered to customers.

Unlike Products and Projects, Releases establish the context in which
enterprise security decisions become meaningful.

Security posture is evaluated per Release because deployed software
differs over time.

The Release therefore owns:

- Findings
- Release-specific metadata
- Security posture
- Historical governance context

This architectural decision was intentionally made during the Domain ADR
discussions to ensure that security decisions remain contextual rather
than global.

------------------------------------------------------------------------

## 4.5 Why Releases Own Findings

Findings describe release-specific observations.

A vulnerability may affect one Release while not affecting another.

Configuration, component versions, backported fixes, deployment models,
and engineering decisions may differ across Releases.

For this reason:

- Findings belong to exactly one Release.
- A Release may own many Findings.
- Findings reference enterprise knowledge through Faultlines.

This separation allows enterprise knowledge to be reused while
governance remains release-specific.

------------------------------------------------------------------------

## 4.6 Relationship to Faultlines

Releases never own enterprise knowledge.

Instead:

``` text
Release
     │
 owns
     ▼
Finding
     │
references
     ▼
Faultline
```

The Release owns the enterprise's observation.

The Faultline represents reusable enterprise knowledge.

This distinction prevents duplication of enterprise reasoning across
multiple Releases.

------------------------------------------------------------------------

## 4.7 Domain Invariants

The Product hierarchy obeys several invariants.

- Every Project belongs to exactly one Product.
- Every Release belongs to exactly one Project.
- Every Finding belongs to exactly one Release.
- Releases never own Faultlines.
- Products never directly own Findings.
- Governance begins at the Release boundary.

These invariants define one of the most stable structures within the
Domain.

------------------------------------------------------------------------

## Domain Invariant 4 --- Release Is the Governance Boundary

Security governance is performed within the context of a Release.

Products and Projects provide organizational context.

Releases provide decision context.

Every Finding belongs to exactly one Release, while enterprise knowledge
is shared through Faultlines.

------------------------------------------------------------------------

## Chapter Summary

Key observations include:

- Products, Projects, and Releases define the enterprise business
    hierarchy.
- Releases are the primary governance boundary.
- Findings are owned by Releases.
- Faultlines remain enterprise-wide knowledge identities.
- The separation between Release ownership and Faultline knowledge
    enables enterprise knowledge reuse while preserving release-specific
    governance.

The next chapter introduces **Evidence**, the first immutable business
concept within the Enterprise Knowledge lifecycle.
