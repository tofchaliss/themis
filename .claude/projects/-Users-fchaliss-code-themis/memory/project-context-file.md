---
name: project-context-file
description: How to use PROJECT_CONTEXT.md, README.md, and openspec/ as canonical context
metadata:
  type: reference
---

# Project Context Sources

## 1. AGENTS.md (repo root) — read first

Single entry point for AI agents. Contains:

- Context source priority table
- OpenSpec layout (current change + archive path)
- Group 16 open task table (9 tasks; gate before Phase 2 starts)
- Permanent invariants (never violate)
- How-to-work workflow

## 2. PROJECT_CONTEXT.md (repo root)

Canonical multi-phase reference. Read at session start.

Covers: core concepts, Five-Layer Data Model (L0–L3), Clean Architecture,
tech stack, six quality gates, Phase 1–3 roadmap, API conventions,
VEX invariants, trust policies, OpenSpec artifact index.

Key update (Phase 2): now describes `AIWorkerRuntime`, `SecurityKnowledgeGraph`,
and `StubVerifier` (Phase 1/2 stub; CosignVerifier deferred to Phase 3).

## 3. README.md (repo root)

Operational and contributor context.

Covers: capabilities summary, build/run (`make build`, `make check`), config env vars,
migrations, testing (`THEMIS_TEST_DATABASE_DSN`, integration tag), coverage targets,
code structure tree.

## 4. openspec/ (guardrails + implementation truth)

| File | Purpose |
| ---- | ------- |
| `config.yaml` | OpenSpec schema |
| `changes/themis-phase-2/proposal.md` | Phase 2 scope, capabilities, prerequisites |
| `changes/themis-phase-2/design.md` | 16 ADRs; open questions OQ-4 through OQ-10 |
| `changes/themis-phase-2/scenario-fresh-deployment.md` | Cold-start gap analysis |
| `changes/archive/2026-06-09-themis-phase-1/tasks.md` | Phase 1 history; Group 16 §16 |
| `changes/archive/2026-06-09-themis-phase-1/design.md` | Phase 1 ADRs (reference) |

## Workflow

1. Read `AGENTS.md` (entry point + Group 16 status)
2. Read relevant section of Phase 2 `proposal.md` and matching `design.md` ADRs
3. Check `scenario-fresh-deployment.md` for cold-start gaps relevant to the task
4. Implement; run `make check`
5. For Phase 2 tasks, update tasks.md (to be created) when tasks are written

Related: [[project-themis-phases]], [[openspec-workflow]]
