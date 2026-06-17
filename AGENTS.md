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
├── STATUS.md                                       # Project status — read this for current state
├── config.yaml                                     # OpenSpec schema + project context
├── changes/
│   ├── themis-phase-2/                             # Architecture reference (NOT an implementation change)
│   │   ├── proposal.md                             # Master design: why / capabilities by sub-phase
│   │   ├── design.md                               # 16 ADRs + open questions OQ-4 to OQ-10
│   │   └── scenario-fresh-deployment.md            # Cold-start E2E analysis; 10 identified gaps
│   ├── themis-phase-2a/                            # COMPLETE — Signal Foundation (v0.2.0)
│   │   ├── proposal.md
│   │   ├── design.md
│   │   ├── tasks.md                                # Groups 1–30 done (30.7–30.8 merge/tag manual)
│   │   └── specs/<capability>/spec.md
│   ├── themis-phase-2b/                            # PLANNED — AI Intelligence (v0.3.0)
│   ├── themis-phase-2c/                            # PLANNED — AI-Assisted VEX (v0.4.0)
│   └── archive/2026-06-09-themis-phase-1/          # Archived — reference only
│       ├── proposal.md
│       ├── design.md                               # 17 Phase 1 ADRs
│       ├── tasks.md                                # Groups 1–16 (Group 16 has 9 open items)
│       └── specs/<capability>/spec.md
```

**Active implementation change:** `themis-phase-2b` (planned). Phase 2a implementation complete on branch `themis-phase-2`; merge to `main` and tag `v0.2.0` pending release sequencing (see tasks §30.7–30.8).

Do not implement Phase 3 features (rate limiting, cosign, CI/CD, Docker, UI, Redis, RBAC)
without explicit user direction.

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

**Phase 1 — Group 16 hardening remainder (targets v0.2.1):** `v0.1.0` is already tagged
(retroactively on the Phase 1 commit, replacing `themis-phase-1`), so the old "gate before
`v0.1.0`" framing is retired. The hardening tasks ship in the `v0.2.1` maintenance release;
the two registration endpoints moved to `themis-core-model`.
Track in `project-backlog.md` (§ "Group 16 — Phase 1 hardening remainder") and detailed
sub-tasks in `openspec/changes/archive/2026-06-09-themis-phase-1/tasks.md` §16.

| # | Task | Target |
| --- | --- | --- |
| 16.1 | Normalise Alpine package names for OSV queries (`so:` prefix, `py3-foo` → `python3-foo`) | v0.2.1 |
| 16.2 | Integration test: Alpine SBOM ingest → non-zero `component_vulnerabilities` | v0.2.1 |
| 16.3 | Integration test: rpm SBOM → ingest succeeds, OSV skip logged cleanly | v0.2.1 |
| 16.4 | Artifact registration endpoint | → `themis-core-model` |
| 16.5 | Upload helper script (`make upload-sbom` or curl wrapper) | v0.2.1 |
| 16.6 | `make check` passes clean after all hardening items | v0.2.1 |
| 16.7 | `adapter/store/` coverage ≥ 90% | v0.2.1 |
| 16.8 | `adapter/osv/` coverage ≥ 90% | v0.2.1 |
| 16.9 | Tag `v0.1.0` + Phase 1 release notes | **Done** |
| 16.10 | Version registration endpoint | → `themis-core-model` |

**Phase 2 — Split into three sub-phases.**

| Sub-phase | Change | Theme | Status |
| --- | --- | --- | --- |
| 2a | `themis-phase-2a` | Signal Foundation | **Complete (140/148)** — archived 2026-06-17; `v0.2.0`; Group 31 (8 feed-reliability tasks) open as Phase 2b gate |
| 2b | `themis-phase-2b` | AI Intelligence | Planned — blocked on Group 31 + `themis-core-model` |
| 2c | `themis-phase-2c` | AI-Assisted VEX | Planned — blocked on 2b |

Phase 2a deliverables (implemented): EPSS/KEV + ExploitDB sync, Layer 1/2 synchronous enrichment,
composite risk score V2, asset graph registration APIs, upstream vendor VEX (Red Hat/Alpine/Rocky/Wolfi),
VEX export, system status API, SBOM soft-delete, layman error catalogue. No AI in 2a.

Track tasks: `openspec/changes/archive/2026-06-17-themis-phase-2a/tasks.md`. Progress: `openspec/STATUS.md`.
Canonical specs (Phase 1 + 2a merged): `openspec/specs/` (17 capabilities).

## Related docs

- `docs/phase-2a-capabilities.md` — Phase 2a in/out of scope reference (`v0.2.0`)
- `docs/acceptance-criteria.md` — AC-1..15 (Phase 1) and AC-16..24 (Phase 2a)
- `docs/archive/proposal-initial.md` — original proposal with ADRs (historical reference)
- `.claude/skills/openspec-*` — OpenSpec workflow skills (propose, apply, explore, archive, sync)
