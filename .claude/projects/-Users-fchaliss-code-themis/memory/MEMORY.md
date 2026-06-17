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

## Current state (updated 2026-06-17)

- **Phase 1 — COMPLETE.** Archived `openspec/changes/archive/2026-06-09-themis-phase-1/`.
  Tagged **`v0.1.0`** (retroactive tag on Phase 1 commit `a94f3ba`, replaced `themis-phase-1`).
- **Phase 2a — COMPLETE.** Archived `openspec/changes/archive/2026-06-17-themis-phase-2a/`.
  Tagged **`v0.2.0`** (PR #15). Signal Foundation: EPSS/KEV, ExploitDB, Layer 1/2, composite
  risk score V2, asset graph, upstream vendor VEX, VEX export, status API, SBOM management.
- **Canonical spec tree exists** at `openspec/specs/` (17 capabilities, Phase 1 + 2a merged);
  future changes update it via `openspec archive`.
- **Open gates before Phase 2b:**
  - **`themis-core-model`** (HIGHEST PRIORITY) — split `sbom_documents` → `sboms` + `scan_reports`;
    fixes triage loss; adds `version.project_id`. Owns the artifact/version registration endpoints.
  - **Group 31** (8 tasks) — feed-reliability fixes; targets `v0.2.1`.
  - **Group 16 remainder** — Phase 1 hardening; targets `v0.2.1`.
- **Phase 2b / 2c — PLANNED.** Architecture reference still active at
  `openspec/changes/themis-phase-2/` (proposal/design/scenario; reference doc, not implemented).

## Release line

`v0.1.0` (Phase 1) → `v0.2.0` (Phase 2a) → `v0.2.1` (Group 31 + Group 16 hardening) →
`v0.3.0` (themis-core-model + Phase 2b) → `v0.4.0` (Phase 2c). Nothing below `v0.2.0` is
tagged again.

## Group 16 hardening remainder (targets v0.2.1)

| # | Task | Status |
| --- | --- | --- |
| 16.1 | Normalise Alpine package names for OSV queries | → v0.2.1 |
| 16.2 | Integration test: Alpine SBOM ingest | → v0.2.1 |
| 16.3 | Integration test: rpm SBOM | → v0.2.1 |
| 16.4 | Artifact registration endpoint | → `themis-core-model` |
| 16.5 | Upload helper script | → v0.2.1 |
| 16.6 | `make check` clean | → v0.2.1 |
| 16.7 | `adapter/store/` coverage ≥ 90% | → v0.2.1 |
| 16.8 | `adapter/osv/` coverage ≥ 90% | → v0.2.1 |
| 16.9 | Tag v0.1.0 + Phase 1 release notes | **Done** |
| 16.10 | Version registration endpoint | → `themis-core-model` |

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
