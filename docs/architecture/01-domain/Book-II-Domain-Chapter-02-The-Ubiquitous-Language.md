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

### Information

Gathered or machine-produced input that the enterprise has **not yet
accepted** --- a feed's claim about a vulnerability, an external source
or crawl result, an AI recommendation. Information is a *suggestion*: it
may be reconciled, weighted, or rejected. It is never authoritative on
arrival and never becomes business truth until an explicit acceptance
step promotes it into Enterprise Knowledge.

Information reflects an outside (or machine) perspective; Enterprise
Knowledge reflects the enterprise's own considered perspective.

### Enterprise Knowledge

The enterprise's understanding of evidence after correlation,
enrichment, and analysis --- the view the enterprise **stands behind**,
as distinct from the raw Information it was derived from.

The boundary runs *through* the Faultline: the raw source claims
recorded on it are Information; its reconciled enterprise view is
Enterprise Knowledge.

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

Gatherers --- feeds, external sources, and the Intelligence Gateway ---
produce Information only. They never write Enterprise Knowledge directly;
crossing that boundary always requires a deliberate acceptance step
(reconciliation by Knowledge, or a governed decision by Governance).

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

## Domain Invariant 3 --- Gathering Is Not Knowing

Information and Enterprise Knowledge are distinct.

Anything that gathers or generates --- feeds, external sources, crawlers,
or the Intelligence Gateway --- produces Information, never Enterprise
Knowledge. Information becomes Enterprise Knowledge only through an
explicit, governed acceptance step (Knowledge reconciliation, or a
Governance decision). No gatherer writes business truth directly.

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
