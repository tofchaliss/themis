---
name: project-context-file
description: How to use PROJECT_CONTEXT.md, README.md, and openspec/ as canonical context
metadata:
  type: reference
---

# Project Context Sources

## 1. PROJECT_CONTEXT.md (repo root)

Canonical multi-phase reference. Read at session start.

Covers: core concepts, L1/L2/L3 data model, Clean Architecture, tech stack, six quality gates, Phase 1–3 roadmap, API conventions, VEX invariants, trust policies, OpenSpec artifact index.

## 2. README.md (repo root)

Operational and contributor context.

Covers: capabilities summary, build/run (`make build`, `make check`), config env vars, migrations, testing (`THEMIS_TEST_DATABASE_DSN`, integration tag), coverage targets, code structure tree.

## 3. openspec/ (guardrails + implementation truth)

| File | Purpose |
| ---- | ------- |
| `config.yaml` | OpenSpec schema |
| `changes/themis-phase-1/proposal.md` | Scope, capabilities, impact |
| `changes/themis-phase-1/design.md` | Design decisions, ADRs |
| `changes/themis-phase-1/tasks.md` | Task groups with six gates each |
| `changes/themis-phase-1/specs/*/spec.md` | Capability requirements |

## 4. AGENTS.md (repo root)

Single entry point for AI agents — links all sources and workflow steps.

## Workflow

1. Read `AGENTS.md` or this index
2. Read relevant section of `tasks.md` + matching `specs/*/spec.md`
3. Confirm design against `design.md` and `PROJECT_CONTEXT.md`
4. Implement; run `make check`
5. Mark tasks complete in `tasks.md`

Related: [[project-themis-phases]], [[openspec-workflow]]
