# Themis v0.3.11 — consolidate docs into a Kubernetes/Istio-style layout

Release tag: `v0.3.11` (**housekeeping** — no code or schema change; documentation + OpenSpec
bookkeeping only). Reorganises all project documentation under `docs/` into purpose-scoped folders
and refreshes stale context docs to the current v0.3.x / `themis-ai-1` state.

## What changed

- **Docs consolidated under `docs/`** into a Kubernetes/Istio-style layout:
  - `docs/release-notes/` — per-version release notes (`release-notes-v0.2.0` … `v0.3.11`).
  - `docs/current-changes/` — `PROJECT_CONTEXT.md`, `project-backlog.md`, the AI decision log
    (`phase-2b-grilling.md`), `NEXT-STAGE.md`, `themis-ai-use-cases.md`, plus `AGENTS.md`,
    `verification.md`, `acceptance-criteria.md`, and `phase-2a-capabilities.md`.
  - `docs/architecture/` — ADR home (seeded `README.md`) for durable decisions.
  - `docs/archive/` — historical material (`proposal-initial.md`, the 9 original ADRs).
- **All references repointed** — `README.md` (new **Documentation** section + links), the
  `PROJECT_CONTEXT.md` reference table, `openspec/config.yaml`,
  `openspec/changes/themis-ai-1/design.md`, and `scripts/alpine-e2e-gate.sh`. Every clickable link
  in the docs tree resolves.
- **Stale context refreshed** — `AGENTS.md` rewritten (OpenSpec layout + active change →
  `themis-ai-1` v0.4.0; release/phase status now deferred to `openspec/STATUS.md`);
  `PROJECT_CONTEXT.md` migrations line → single squashed v0.3.0 baseline (was `000001–000013`);
  `openspec/config.yaml` context → canonical `openspec/specs/` + `STATUS.md`, active change
  `themis-ai-1` (was "Phase 1 only").
- **Shipped as PR #47** on branch `docs-cleanup`.

## Upgrade

Nothing to deploy — documentation and OpenSpec only. No binary, schema, or config change. The Go
build, `make check` / `make verify-build`, and CI are unaffected (nothing in the build references
`docs/`; the only `//go:embed` is `internal/adapter/trust/schemas/*.json`).
