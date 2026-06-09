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
├── config.yaml                                     # OpenSpec schema + project context for artifact generation
├── changes/themis-phase-2/                         # Active change
│   ├── proposal.md                                 # Why / what / capabilities (scope boundary)
│   └── specs/<capability>/spec.md                  # Requirements + acceptance scenarios per capability
└── changes/archive/2026-06-09-themis-phase-1/      # Archived — reference only
    ├── proposal.md
    ├── design.md                                   # 17 Phase 1 ADRs
    ├── tasks.md                                    # Groups 1–16 (Group 16 has 9 open items)
    └── specs/<capability>/spec.md
```

**Current change:** `themis-phase-2`. Do not implement Phase 3 features (rate limiting,
cosign, CI/CD ingestion, Docker, UI, Redis, RBAC) without explicit user direction.

## How to work

1. **Before starting a task group** — read the matching section in the active tasks.md and the relevant `specs/*/spec.md`.
2. **Before design choices** — check `design.md` and `PROJECT_CONTEXT.md` for existing ADRs and invariants.
3. **While implementing** — follow Clean Architecture import rules and the quality gates in `PROJECT_CONTEXT.md`.
4. **Before marking a task group done** — two separate checks, in this order:
   1. **Task-wise gates** — run the gates listed in that group's section of `tasks.md`
      (unit tests, coverage, dead code, integration tests, clean-arch) for the
      **package(s) touched by that group only**. Coverage: `make coverage-pkg PKG=<path>`
      (e.g. `PKG=usecase/enrichment`; path is under `internal/` without the prefix).
      Register new packages in `scripts/check-coverage.sh` first.
   2. **Full codebase build** — `make verify-build` (`make clean` then `make all`) on
      the **entire repo** to confirm nothing else broke.
5. **Scope guardrail** — if a feature belongs to Phase 3 (rate limiting, cosign,
   CI/CD, Docker, UI, Redis, RBAC), defer it.

## Permanent invariants (never violate)

- Raw findings in `component_vulnerabilities` are **never deleted or modified** — VEX changes only `risk_context.effective_state`.
- `internal/domain/` imports stdlib only; use cases import domain only; adapters import domain + usecase.
- Every task group passes task-wise gates (tests, coverage for touched packages, dead
  code, integration, clean-arch) then a full-codebase `make verify-build`.
- Integration tests use `//go:build integration`; external Postgres via
  `THEMIS_TEST_DATABASE_DSN` when embedded Postgres is unavailable.

## Implementation status

**Phase 1 — Group 16 hardening (9 tasks open):** Must be completed before tagging `v0.1.0`.
Track in `project-backlog.md` (§ "Phase 1 — Remaining hardening") and detailed sub-tasks in
`openspec/changes/archive/2026-06-09-themis-phase-1/tasks.md` §16.

| # | Task |
| --- | --- |
| 16.1 | Normalise Alpine package names for OSV queries (`so:` prefix, `py3-foo` → `python3-foo`) |
| 16.2 | Integration test: Alpine SBOM ingest → non-zero `component_vulnerabilities` |
| 16.3 | Integration test: rpm SBOM → ingest succeeds, OSV skip logged cleanly |
| 16.4 | `POST /api/v1/products/{id}/images` — image registration endpoint |
| 16.5 | Upload helper script (`make upload-sbom` or curl wrapper) |
| 16.6 | `make check` passes clean after all Group 16 items |
| 16.7 | `adapter/store/` coverage ≥ 90% |
| 16.8 | `adapter/osv/` coverage ≥ 90% |
| 16.9 | Merge to `main`, git tag `v0.1.0`, Phase 1 release notes |

**Phase 2 — Not started.** See `openspec/changes/themis-phase-2/proposal.md`.

## Related docs

- `docs/acceptance-criteria.md` — 15 acceptance criteria (tested in `tests/acceptance/`)
- `docs/archive/proposal-initial.md` — original proposal with ADRs (historical reference)
- `.claude/skills/openspec-*` — OpenSpec workflow skills (propose, apply, explore, archive, sync)
