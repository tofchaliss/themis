# Agent Context Guide — Themis

Read this file at the start of every session before planning or implementing work.

## Context sources (in order)

| Priority | Source | Use for |
| -------- | ------ | ------- |
| 1 | [`PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md) | Domain model, Clean Architecture, phase scope, invariants, quality gates, API conventions |
| 2 | [`README.md`](README.md) | Build/run/test commands, config, coverage targets, repo layout, contributing workflow |
| 2b | [`verification.md`](verification.md) | Pre-answer checklist: correctness, severity, observability — required before final answers |
| 3 | [`openspec/`](openspec/) | Guardrails, proposals, design decisions, tasks, per-capability specs |

## OpenSpec layout

```text
openspec/
├── config.yaml                          # OpenSpec schema + project context for artifact generation
└── changes/themis-phase-1/
    ├── proposal.md                      # Why / what / capabilities (scope boundary)
    ├── design.md                        # ADRs, architecture, quality gates
    ├── tasks.md                         # Implementation checklist (~15 groups, 6 gates each)
    └── specs/<capability>/spec.md       # Requirements + acceptance scenarios per capability
```

**Current change:** `themis-phase-1` — Phase 1 only. Do not add Phase 2/3 features to Phase 1 specs or code without explicit user direction.

## How to work

1. **Before starting a task group** — read the matching section in `openspec/changes/themis-phase-1/tasks.md` and the relevant `specs/*/spec.md`.
2. **Before design choices** — check `design.md` and `PROJECT_CONTEXT.md` for existing ADRs and invariants.
3. **While implementing** — follow Clean Architecture import rules and the quality gates in `PROJECT_CONTEXT.md`.
4. **Before marking a task group done** — two separate checks, in this order:
   1. **Task-wise gates** — run the gates listed in that group's section of `tasks.md` (unit tests, coverage, dead code, integration tests, clean-arch) for the **package(s) touched by that group only**. Coverage: `make coverage-pkg PKG=<path>` (e.g. `PKG=usecase/enrichment`; path is under `internal/` without the prefix). Register new packages in `scripts/check-coverage.sh` first.
   2. **Full codebase build** — `make verify-build` (`make clean` then `make all`) on the **entire repo** to confirm nothing else broke.
5. **Scope guardrail** — if a feature belongs to Phase 2/3 (AI, EPSS/KEV, cosign, git ingestion, Docker, UI, Redis, RBAC), defer it.

## Permanent invariants (never violate)

- Raw findings in `component_vulnerabilities` are **never deleted or modified** — VEX changes only `risk_context.effective_state`.
- `internal/domain/` imports stdlib only; use cases import domain only; adapters import domain + usecase.
- Every task group passes task-wise gates (tests, coverage for touched packages, dead code, integration, clean-arch) then a full-codebase `make verify-build`.
- Integration tests use `//go:build integration`; external Postgres via `THEMIS_TEST_DATABASE_DSN` when embedded Postgres is unavailable.

## Implementation status

Track progress in `openspec/changes/themis-phase-1/tasks.md`. **Phase 1 complete — all 15 task groups (192/192) done.**

## Related docs

- `docs/acceptance-criteria.md` — 15 acceptance criteria (tested in `tests/acceptance/`)
- `docs/archive/proposal-initial.md` — original proposal with ADRs (historical reference)
- `.claude/skills/openspec-*` — OpenSpec workflow skills (propose, apply, explore, archive, sync)
