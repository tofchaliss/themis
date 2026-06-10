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
| `openspec/changes/themis-phase-2/proposal.md` | Scope boundary, capabilities, why/what, Phase 2 prerequisites |
| `openspec/changes/themis-phase-2/design.md` | 16 ADRs, open questions OQ-4 through OQ-10 |
| `openspec/changes/themis-phase-2/scenario-fresh-deployment.md` | Cold-start E2E walkthrough; 10 gaps |
| `openspec/changes/archive/2026-06-09-themis-phase-1/tasks.md` | Phase 1 history; Group 16 §16 detail |
| `openspec/changes/archive/2026-06-09-themis-phase-1/design.md` | 17 Phase 1 ADRs (reference only) |

## Phase 2 capabilities (to be specced)

- `ai-enrichment` — 3-layer Intelligence Collector, 7 AI workers, RAG, KB-first, async JobQueue
- `epss-kev` — FIRST.org EPSS + CISA KEV sync → intelligence_signals
- `upstream-vex-feeds` — scheduled vendor VEX feed fetch (Red Hat, Alpine, Ubuntu, etc.)
- `vex-export` — AI + human triage → CycloneDX VEX document generation

Spec files go in: `openspec/changes/themis-phase-2/specs/<capability>/spec.md`

## Phase 1 capability specs (archived — reference only)

Path: `openspec/changes/archive/2026-06-09-themis-phase-1/specs/*/spec.md`

- `artifact-trust` — trust gate, dedup, provenance, StubVerifier
- `sbom-parser` — CycloneDX/SPDX/Trivy → CanonicalSBOM
- `sbom-ingestion` — upload/webhook pipeline, idempotency, lifecycle
- `sbom-store` — PostgreSQL schema
- `intelligence-enrichment` — VEX overlay, effective state, risk score
- `cve-triage` — triage, themis-generated VEX, history
- `cve-watch` — NVD/OSV polling, catalog matching
- `notification-service` — SMTP, Teams, routing rules

## Skills (`.claude/skills/`)

- `openspec-propose` — new change with proposal + design + specs + tasks
- `openspec-apply-change` — implement from tasks.md
- `openspec-explore` — explore ideas before committing
- `openspec-sync-specs` — sync delta specs to main specs
- `openspec-archive-change` — archive completed change

## Phase guardrail

Phase 3 features (rate limiting, cosign, CI/CD ingestion, Docker, UI, Redis, RBAC)
must NOT be implemented until explicitly requested.

Related: [[project-themis-phases]], [[project-context-file]]
