# Book II --- The Themis Enterprise Security Domain

## Part I --- Understanding the Domain

## Chapter 1 --- Why Enterprise Security Needs a Domain Model

> *"Software is built from code. Enterprises are built from shared
> understanding. A domain model exists to preserve that understanding."*

## Chapter Objective

After reading this chapter, the reader should understand:

- Why enterprise security is fundamentally a business domain rather
    than a collection of technical tools.
- Why a shared domain language is essential for long-term
    architectural consistency.
- Why Themis begins with a domain model instead of implementation.
- How the Domain book relates to the Constitution and the Backend
    Architecture.

------------------------------------------------------------------------

## 1.1 Beyond Security Tools

Enterprise security is often perceived as a collection of technologies
such as vulnerability scanners, Software Composition Analysis (SCA),
Software Bills of Materials (SBOMs), security advisories, dashboards,
ticketing systems, and compliance reports.

These technologies are important, but they are not the domain.

They are instruments used to observe and manage a much larger business
reality.

An enterprise must continuously answer questions such as:

- Which products are affected?
- Which releases require action?
- Which customer commitments must be honoured?
- What is the organisation's official position?
- Why was that position reached?
- How has that position evolved?

These are business questions before they are technical questions.

------------------------------------------------------------------------

## 1.2 The Problem of Fragmented Language

Engineering, security, product management, operations and customers
frequently describe the same reality using different terminology.

Without a shared language:

- automation becomes inconsistent,
- reports contradict one another,
- knowledge is duplicated,
- architectural boundaries become unclear.

A domain model establishes a common language for the enterprise.

------------------------------------------------------------------------

## 1.3 Why a Domain Model Exists

A domain model does not describe software components.

It describes the business concepts that software exists to support.

Within Themis, concepts such as Evidence, Faultline, Finding, Enterprise
Knowledge and Enterprise Position are business concepts with precise
meaning, ownership and relationships.

The software reflects the domain rather than defining it.

------------------------------------------------------------------------

## 1.4 Enterprise Security as a Knowledge Domain

Traditional vulnerability management platforms focus on collecting and
presenting information.

Themis models how an enterprise understands, governs and communicates
security knowledge.

Rather than asking:

"What vulnerabilities exist?"

The enterprise asks:

"What do these observations mean for our products, releases, customers
and commitments?"

------------------------------------------------------------------------

## 1.5 The Role of This Book

The Constitution established the philosophy of Themis.

This book defines the business universe in which that philosophy
operates.

Every business concept introduced here will later be realised by the
Backend Architecture.

Accordingly, this book focuses exclusively on business language,
ownership, relationships, behaviour and invariants.

------------------------------------------------------------------------

## Domain Insight

A domain model is not a description of software.

It is a description of the enterprise reality that the software must
faithfully represent.

------------------------------------------------------------------------

## Chapter Summary

- Enterprise security is a business domain with multiple stakeholders.
- A shared language is essential for architectural consistency.
- Themis models enterprise understanding rather than security tooling.
- The Domain book defines business truth; the Backend book realises
    it.

The next chapter introduces the Ubiquitous Language of Themis.
