# Book II --- The Themis Enterprise Security Domain

## Part I --- Understanding the Domain

## Chapter 2 --- The Ubiquitous Language

> *"A shared language is the foundation of a shared understanding.
> Without it, every system eventually models a different enterprise."*

## Chapter Objective

After reading this chapter, the reader should understand:

- Why Themis adopts a ubiquitous language.
- How business terminology differs from technical terminology.
- The core business concepts that appear throughout the architecture.
- Why consistent language is essential for architectural integrity.

------------------------------------------------------------------------

## 2.1 Why Language Matters

Enterprise security involves product managers, software architects,
developers, security analysts, release managers, customer support teams,
auditors, and customers. Each group naturally develops its own
vocabulary.

When the same concept is described using different terms, ambiguity
becomes inevitable. Ambiguity eventually produces inconsistent reports,
conflicting decisions, and architectural drift.

Themis therefore adopts a single ubiquitous language that is used
consistently across documentation, domain models, architecture, APIs,
and implementation.

------------------------------------------------------------------------

## 2.2 Principles of the Ubiquitous Language

The language of Themis follows five principles:

- Every important business concept has one authoritative name.
- One name represents one business meaning.
- Technical implementation must never redefine business terminology.
- New terminology requires architectural review.
- Documentation, code, and conversations should use the same
    vocabulary.

------------------------------------------------------------------------

## 2.3 Core Business Vocabulary

### Product

The highest business entity representing a deliverable offered by the
enterprise.

### Project

A logical subdivision of a Product that evolves independently while
contributing to the overall product.

### Release

A governed business snapshot of one or more Projects delivered to
customers.

### Evidence

An immutable observation relevant to the enterprise.

### Enterprise Knowledge

The enterprise's understanding of evidence after correlation,
enrichment, and analysis.

### Faultline

The enterprise-wide knowledge identity that groups related enterprise
understanding across products and releases.

A Faultline is **not** owned by a Release. It exists independently and
may be referenced by many Findings.

### Finding

A release-specific security observation owned by Governance.

Each Finding references exactly one Faultline.

### Enterprise Position

The authoritative business decision established by Governance for a
Finding or related business concern.

### Communication

A published representation of an Enterprise Position prepared for a
specific audience.

Communication never becomes business truth.

------------------------------------------------------------------------

## 2.4 Vocabulary and Ownership

Names are not merely labels.

Each business concept has a clearly defined owner.

- Evidence owns observations.
- Knowledge owns Faultlines and Enterprise Knowledge.
- Governance owns Findings and Enterprise Positions.
- Communication owns published artifacts.

Ownership gives terminology operational meaning.

------------------------------------------------------------------------

## 2.5 Language as an Architectural Boundary

The ubiquitous language forms a contract between business and
implementation.

Developers may introduce new classes.

Architects may introduce new services.

Infrastructure may introduce new deployment models.

None of these should change the business meaning of Product, Release,
Faultline, Finding, Enterprise Position, or Evidence.

The language remains stable while implementations evolve.

------------------------------------------------------------------------

## Domain Invariant 2 --- One Concept, One Meaning

Every significant business concept within Themis has exactly one
authoritative definition.

Alternative terminology, aliases, or implementation-specific meanings
shall not replace the ubiquitous language.

------------------------------------------------------------------------

## Chapter Summary

Key observations include:

- The ubiquitous language provides a shared vocabulary across the
    enterprise.
- Business concepts are independent of implementation.
- Ownership reinforces terminology.
- Stable language prevents architectural drift.

The next chapter introduces Enterprise Security as a Knowledge Domain
and explains why Themis models enterprise understanding rather than
vulnerability data.
