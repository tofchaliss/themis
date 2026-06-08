# Memory Index — Themis

## Context workflow (read every session)

1. **`PROJECT_CONTEXT.md`** (repo root) — canonical domain + architecture + phase roadmap
2. **`README.md`** — operational commands, config, testing, contributing
3. **`openspec/`** — proposals, design, tasks, capability specs (guardrails)
4. **`AGENTS.md`** — agent entry point tying the above together

## Memory files

- [Themis Phase Breakdown](project-themis-phases.md) — Phase 1/2/3 scope, key decisions, what belongs where
- [Project Context File](project-context-file.md) — how to use PROJECT_CONTEXT.md and OpenSpec
- [OpenSpec Workflow](openspec-workflow.md) — which OpenSpec files to read when

## Current state

- OpenSpec change: `openspec/changes/themis-phase-1/`
- Task groups 1–14 complete; **Group 15** (final E2E / full-repo gates) remains

## Gating procedure (every completed task group)

**Order matters — two separate checks:**

1. **Task-wise gates** (packages touched by the group only):
   - `go test ./internal/<package>/...`
   - `make coverage-pkg PKG=<path>` (e.g. `PKG=usecase/triage`; register new packages in `scripts/check-coverage.sh`)
   - `make deadcode` / `make clean-arch` when the group lists them
   - Integration tests: `go test -tags=integration ./internal/<package>/... -run <TestName>`
2. **Full codebase** (always last): `make verify-build` (`make clean` then `make all`)

Full-repo `make coverage` / `make check` is for Group 15 / CI sweeps, not required on every group.

## Invariants

- VEX overlay only — never delete/modify `component_vulnerabilities`
- Phase 1: no AI, EPSS/KEV, real cosign, git CI, Docker prod stack, UI, Redis, RBAC
- Coverage: 100% domain/usecase/parser/trust/notify; ≥90% store/api/infrastructure
