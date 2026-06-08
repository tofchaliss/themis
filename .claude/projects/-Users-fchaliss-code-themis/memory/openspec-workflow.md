---
name: openspec-workflow
description: Which OpenSpec files to read for proposals, design, tasks, and capability specs
metadata:
  type: workflow
---

# OpenSpec Workflow — Themis

OpenSpec is the guardrail and thought-process layer. Always consult it before implementing or changing scope.

## Directory map

| Path | When to read |
| ---- | ------------ |
| `openspec/config.yaml` | OpenSpec schema; optional project context for artifact generation |
| `openspec/changes/themis-phase-1/proposal.md` | Scope boundary, capabilities, why/what |
| `openspec/changes/themis-phase-1/design.md` | ADRs, Clean Architecture, quality gates, technical decisions |
| `openspec/changes/themis-phase-1/tasks.md` | Implementation checklist; mark `[x]` only after gates pass |
| `openspec/changes/themis-phase-1/specs/*/spec.md` | Per-capability requirements and acceptance scenarios |

## Capability specs (Phase 1)

- `artifact-trust` — trust gate, dedup, provenance, StubVerifier
- `sbom-parser` — CycloneDX/SPDX/Trivy → CanonicalSBOM
- `sbom-ingestion` — upload/webhook pipeline, idempotency, lifecycle
- `sbom-store` — PostgreSQL three-layer schema
- `intelligence-enrichment` — VEX overlay, effective state, risk score
- `cve-triage` — L4 triage, themis-generated VEX, history
- `cve-watch` — NVD/OSV polling, catalog matching
- `notification-service` — SMTP, Teams, routing rules

## Skills (`.claude/skills/`)

- `openspec-propose` — new change with proposal + design + specs + tasks
- `openspec-apply-change` — implement from tasks.md
- `openspec-explore` — explore ideas before committing
- `openspec-sync-specs` — sync delta specs to main specs
- `openspec-archive-change` — archive completed change

## Phase guardrail

If a feature is Phase 2/3 (AI, EPSS/KEV, cosign, GitHub/GitLab ingestion, Docker, UI, Redis, RBAC), do **not** add it to Phase 1 specs or code without explicit user request.

Related: [[project-themis-phases]], [[project-context-file]]
