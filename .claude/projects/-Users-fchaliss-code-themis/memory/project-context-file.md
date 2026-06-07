---
name: project-context-file
description: PROJECT_CONTEXT.md at repo root is the canonical multi-phase reference document for Themis
metadata:
  type: reference
---

`PROJECT_CONTEXT.md` at the root of `/Users/fchaliss/code/themis/` is the canonical
entry-point document for the Themis project. Read it at the start of any new session.

It covers:
- Core concepts (SBOM, VEX, PURL, risk_context, effective_state, VEX overlay)
- Three-layer data model (L1/L2/L3) and convergence table
- Clean Architecture layer map and import rules
- Full technology stack
- Six mandatory code quality gates
- Phase 1 capabilities and constraints
- Phase 2 planned capabilities (AI, EPSS/KEV, cosign, GitHub/GitLab)
- Phase 3 planned capabilities (Docker, Redis, UI, Bitbucket, RBAC/OIDC)
- API conventions (versioning, pagination, RFC 7807, async, idempotency)
- VEX overlay semantics (raw findings never deleted — permanent invariant)
- Trust policy levels (strict/standard/permissive)
- Index of all detailed OpenSpec artifacts

Related: [[project-themis-phases]]
