# Memory Index — Themis

## Context workflow (read every session)

1. **`AGENTS.md`** (repo root) — agent entry point; links all sources; Group 16 status table
2. **`PROJECT_CONTEXT.md`** (repo root) — canonical domain + architecture + phase roadmap
3. **`README.md`** — operational commands, config, testing, contributing
4. **`openspec/`** — proposals, design, tasks, capability specs (guardrails)

## Memory files

- [Themis Phase Breakdown](project-themis-phases.md) — Phase 1/2/3 scope, key decisions, what belongs where
- [Project Context File](project-context-file.md) — how to use PROJECT_CONTEXT.md and OpenSpec
- [OpenSpec Workflow](openspec-workflow.md) — which OpenSpec files to read when

## Current state

- **Phase 1 — COMPLETE.** Archived at `openspec/changes/archive/2026-06-09-themis-phase-1/`
- **Phase 1 — Group 16 hardening (9 tasks OPEN).** Must complete before tagging `v0.1.0` and
  starting Phase 2. Tracked in `AGENTS.md` §Implementation Status and
  `openspec/changes/archive/2026-06-09-themis-phase-1/tasks.md` §16.
- **Phase 2 — NOT STARTED.** Active change at `openspec/changes/themis-phase-2/`
  - `proposal.md` — Why / what / capabilities + Prerequisites (Group 16 gate)
  - `design.md` — 16 ADRs; open questions OQ-4 through OQ-10
  - `scenario-fresh-deployment.md` — E2E cold-start analysis; 10 identified gaps

## Group 16 open tasks (gate for Phase 2)

| # | Task |
| --- | --- |
| 16.1 | Normalise Alpine package names for OSV queries |
| 16.2 | Integration test: Alpine SBOM ingest |
| 16.3 | Integration test: rpm SBOM |
| 16.4 | `POST /api/v1/products/{id}/images` — image registration endpoint |
| 16.5 | Upload helper script |
| 16.6 | `make check` clean |
| 16.7 | `adapter/store/` coverage ≥ 90% |
| 16.8 | `adapter/osv/` coverage ≥ 90% |
| 16.9 | Merge to main, tag v0.1.0 |

## Gating procedure (every completed task group)

**Order matters — two separate checks:**

1. **Task-wise gates** (packages touched by the group only):
   - `go test ./internal/<package>/...`
   - `make coverage-pkg PKG=<path>`
   - `make deadcode` / `make clean-arch` when the group lists them
   - Integration tests: `go test -tags=integration ./internal/<package>/...`
2. **Full codebase** (always last): `make verify-build` (`make clean` then `make all`)

## Invariants

- VEX overlay only — never delete/modify `component_vulnerabilities`
- Phase 2 scope: AI enrichment, EPSS/KEV, upstream VEX feeds, VEX export
- Phase 3 (do not implement): rate limiting, cosign, CI/CD, Docker, UI, Redis, RBAC
- Coverage: 100% domain/usecase/parser/trust/notify; ≥90% store/api/infrastructure
