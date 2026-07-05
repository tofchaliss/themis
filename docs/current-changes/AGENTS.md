# Agent Context Guide — Themis

Read this file at the start of every session before planning or implementing work.

## Context sources (in order)

| Priority | Source | Use for |
| -------- | ------ | ------- |
| 1 | [`PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md) | Domain model, Clean Architecture, phase scope, invariants, quality gates, API conventions |
| 2 | [`README.md`](../../README.md) | Build/run/test commands, config, coverage targets, repo layout, contributing workflow |
| 2b | [`verification.md`](verification.md) | Pre-answer checklist: correctness, severity, observability — required before final answers |
| 3 | [`../../openspec/`](../../openspec/) | Guardrails, proposals, design decisions, tasks, per-capability specs |

## OpenSpec layout

```text
openspec/
├── STATUS.md                    # Project status — read FIRST for authoritative current state
├── config.yaml                  # OpenSpec schema + project context
├── specs/<capability>/spec.md   # Canonical capability specs (Phase 1 + 2a merged) — source of truth
├── intel-source-tiers.md
└── changes/
    ├── themis-ai-1/             # ACTIVE — Basic AI Enrichment / CVE Summarizer (v0.4.0); planning complete
    ├── themis-phase-2/          # Architecture reference (NOT an implementation change)
    └── archive/                 # Completed changes: themis-phase-1, -phase-2a, -v0-2-1, -core-model
```

**Active change:** `themis-ai-1` — v0.4.0 Basic AI Enrichment (advisory CVE Summarizer: 1 worker,
Ollama `qwen2.5:7b`, two systems over a Postgres seam). Planning complete (proposal · design · spec
· 46 tasks); ready to implement. Phases 1 / 2a / core-model are shipped and archived. See
[`../../openspec/STATUS.md`](../../openspec/STATUS.md) for the authoritative, always-current status.

Do not implement Phase 3 features (rate limiting, cosign, CI/CD, Docker, UI, Redis, RBAC)
without explicit user direction.

## How to work

1. **Before starting a task group** — read the matching section in the active `tasks.md` and the relevant `specs/*/spec.md`.
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
5. **Scope guardrail** — implement only what the active change covers; if a feature belongs to a
   later phase (e.g. Phase 3: rate limiting, cosign, CI/CD, Docker, UI, Redis, RBAC), defer it.

## Permanent invariants (never violate)

- Raw findings in `component_vulnerabilities` are **never deleted or modified** — VEX changes only `risk_context.effective_state`.
- `internal/domain/` imports stdlib only; use cases import domain only; adapters import domain + usecase.
- Every task group passes task-wise gates (tests, coverage for touched packages, dead
  code, integration, clean-arch) then a full-codebase `make verify-build`.
- Integration tests use `//go:build integration`; external Postgres via
  `THEMIS_TEST_DATABASE_DSN` when embedded Postgres is unavailable.

## Implementation status

Authoritative, always-current status lives in **[`../../openspec/STATUS.md`](../../openspec/STATUS.md)**
(maintained by the OpenSpec skills). Do not duplicate release/phase status here.

**Snapshot (2026-07):** Phases 1 and 2a, and the `v0.3.0` core-model + Layer-0 refactor, are
**shipped and archived**; the `v0.3.2`–`v0.3.10` maintenance line is released. The active change is
**`themis-ai-1`** (v0.4.0 Basic AI Enrichment). Canonical capability specs (Phase 1 + 2a merged,
18 capabilities): `../../openspec/specs/`.

## Related docs

- `phase-2a-capabilities.md` — Phase 2a in/out of scope reference (`v0.2.0`)
- `acceptance-criteria.md` — AC-1..15 (Phase 1) and AC-16..24 (Phase 2a)
- `../archive/proposal-initial.md` — original proposal with ADRs (historical reference)
- `NEXT-STAGE.md` — v0.4.1+ roadmap (everything deferred beyond the v0.4.0 thin slice)
- `../../.claude/skills/openspec-*` — OpenSpec workflow skills (propose, apply, explore, archive, sync)
