# Design — phase3-shared-kernel (Shared Kernel, M2)

## Source of truth

All engineering decisions (rationale + rejected alternatives) live in
**`docs/engineering/decisions/EDR-KERNEL-01.md` (D1–D4)**. This document states layout, admission rule,
import rules, and gates only.

## Layout

Two separate trees, because one is behavior-free and one is stateful:

```text
internal/kernel/     BEHAVIOR-FREE value kernel — imported by everyone
├── value/           CVE-ID, PURL, ContentFingerprint (SHA-256), CVSS, Severity
├── id/              typed-ID / UUID helper, clock
└── event/           integration-event envelope contract (+ JSON schema)

internal/registry/   STATEFUL supporting context — owns Product/Project/Release identity
├── domain/          Product, Project, Release aggregates (identity + structure; no security state)
├── app/             Register* + lookup use cases, incl. ReleaseExists (backs Evidence SubjectRef)
└── adapters/        Postgres (products/projects/releases) + http
```

## Admission rule for the value kernel (D3 · ADR-CON-0001)

A member enters `internal/kernel/` only if it is (1) used by every stage, (2) stable, (3) not owned by
any context, and (4) **behavior-free**. This keeps the kernel from becoming the "central shared
repository" ADR-CON-0001 rejects. The registry is deliberately **not** in `kernel/` — it has behavior.

## Import rules

- `internal/kernel/` imports **nothing** from any context or from `registry/` (it is the leaf).
- Every context and `registry/` may import `internal/kernel/`.
- Contexts reference the registry only through its **API / read model** (e.g. `ReleaseExists`), never its
  tables (Book III §3.5). Enforced by `go-cleanarch` + depguard + an architecture test.

## Ownership (D1 · D2)

- Registry owns **Product → Project → Release** structural identity only.
- Governance owns Findings / Enterprise Positions / posture, keyed to a Release it references (unchanged).
- No Artifact entity; the image digest is Evidence provenance (D2).

## Event plumbing boundary (D4)

The **envelope** (value shape) lives in `internal/kernel/event/`. The **outbox runner + bus** are
**Event Infrastructure (M5)**, not this change. Specific event types are owned by their publishing
context.

## Stack

Canonical stack + rationale: **`docs/engineering/STACK.md`** (read before implementing). Kernel-specific:
pure Go value objects (only `google/uuid` for typed IDs; no other deps); the registry uses **pgx** +
**golang-migrate** for its own `products`/`projects`/`releases` tables and **chi** + **oapi-codegen** for
register/lookup. **No outbox here** — the kernel provides the event *envelope* contract only (D4).

## Quality gates

The six Themis gates (`make check`) — build, unit tests, coverage, dead-code, integration tests,
clean-architecture — extended to `internal/kernel/` and `internal/registry/`. Markdown passes
`markdownlint-cli2`.
