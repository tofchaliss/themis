# Book III --- The Themis Backend Architecture

## Part I --- Realizing the Domain

## Chapter 1 --- Why Backend Architecture Exists

> *"The Backend does not define the enterprise. It faithfully executes
> the enterprise."*

------------------------------------------------------------------------

## Chapter Objective

After reading this chapter, the reader should understand:

- Why the Backend Architecture exists.
- Why the backend realizes the Domain rather than defining it.
- The constitutional responsibilities of the backend.
- Why bounded contexts are architectural units while services are
    implementation units.
- How the backend preserves business integrity during execution.

------------------------------------------------------------------------

## 1.1 The Misconception of Backend Architecture

Many software architecture books begin by describing servers, APIs,
databases, messaging systems, or microservices. These technologies are
important, but they are not the architecture.

Imagine two implementations of the same Enterprise Security Domain.

- One is written in Python using FastAPI.
- One is written in Java using Spring Boot.
- One stores data in PostgreSQL.
- One stores data in MongoDB.
- One is deployed as a modular monolith.
- One is deployed as distributed microservices.

If both systems receive the same enterprise evidence, they should reach
the same enterprise decisions.

If changing a programming language, framework, or database changes
business behaviour, then implementation has become the architecture.

Themis rejects this approach.

The Backend Architecture exists to ensure that implementation faithfully
realizes the Enterprise Security Domain without redefining it.

------------------------------------------------------------------------

## 1.2 The Backend Is Not the Business

The Constitution established the architectural philosophy.

The Domain book defined the business language, aggregates, ownership,
and behaviour.

The Backend introduces no new business concepts.

Instead, it provides the execution model that preserves those concepts
while software performs work.

The backend therefore realizes the Domain; it never replaces it.

------------------------------------------------------------------------

## 1.3 The Mission of the Backend

The backend has six constitutional responsibilities:

1. Execute business use cases.
2. Protect aggregate invariants.
3. Maintain transactional consistency.
4. Publish authoritative business events.
5. Recover safely from failure.
6. Preserve explainability and auditability.

Anything outside these responsibilities belongs either to the Domain or
to implementation-specific infrastructure.

------------------------------------------------------------------------

## 1.4 Business Execution Before Technology

Themis organizes its backend around business responsibilities rather
than technology.

The architectural progression is:

``` text
Business Responsibility
        ↓
Architectural Capability
        ↓
Implementation
```

Business intent always drives implementation.

Technology is selected to realize architecture---not to define it.

------------------------------------------------------------------------

## 1.5 Bounded Contexts Before Services

A common mistake is to view a backend as a collection of services.

Themis instead views the backend as a collection of bounded contexts
that happen to expose services.

Bounded contexts own business capabilities.

Services implement use cases within those capabilities.

This distinction ensures that ownership remains architectural rather
than technical.

------------------------------------------------------------------------

## 1.6 Backend Constitutional Principles

Every backend decision shall satisfy the following principles:

- The Backend realizes the Domain. It never redefines it.
- Every backend component protects one or more Domain invariants.
- Every backend decision is traceable to the Constitution, the Domain
    Model, or a Backend ADR.
- Ownership shall never be violated for implementation convenience.
- Race conditions shall be prevented through architecture before they
    are mitigated through code.

These principles apply regardless of language, framework, or deployment
model.

------------------------------------------------------------------------

## 1.7 Architectural Pressures

Each bounded context experiences different operational pressures.

- **Evidence** prioritizes ingestion, validation, and provenance.
- **Knowledge** prioritizes correlation, enrichment, and continuous
    evolution.
- **Governance** prioritizes traceability, accountability, and
    authoritative decision making.
- **Communication** prioritizes reliable publication and
    audience-specific materialization.

Recognizing these pressures allows implementation choices to remain
aligned with business intent.

------------------------------------------------------------------------

## 1.8 Implementation Readiness Checklist

| Question | Status |
| --- | --- |
| Is the Domain the source of business meaning? | ✓ |
| Are ownership boundaries preserved? | ✓ |
| Are backend responsibilities defined? | ✓ |
| Are bounded contexts recognized as architectural units? | ✓ |
| Are transaction boundaries defined? | Introduced in later chapters |
| Are repositories and events implementation details? | Addressed in subsequent chapters |

------------------------------------------------------------------------

## Backend Principle 1

**The Backend realizes the Enterprise Security Domain. It never
redefines it.**

## Backend Principle 2

**Every backend component exists to preserve one or more Domain
invariants.**

## Backend Principle 3

**Every backend decision shall be traceable to a Constitutional
Principle, a Domain concept, or a Backend ADR.**

------------------------------------------------------------------------

## Chapter Summary

This chapter establishes the purpose of the Backend Architecture.

The backend is not the source of business truth. It is the disciplined
realization of the Enterprise Security Domain. By preserving ownership,
invariants, consistency, explainability, and controlled evolution, the
backend protects the integrity of the architecture while executing
enterprise business operations.

The next chapter introduces the Backend Design Principles that guide
every implementation decision within Themis.
