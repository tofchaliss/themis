# Themis v0.3.10 — archive themis-core-model; docs current to v0.3.9

Release tag: `v0.3.10` (**housekeeping** — no code or schema change; documentation + OpenSpec
bookkeeping only). Closes out the `themis-core-model` change and brings the status/context docs
level with the shipped v0.3.x line.

## What changed

- **`themis-core-model` archived.** Final task 9.6 (the release-coordination gate — "don't tag
  v0.3.0 until Phase 2b is ready") is ticked as **superseded**: v0.3.0 shipped standalone
  (tagged 2026-06-24) and Phase 2b was re-scoped to v0.4.0. All **58/58** tasks complete. The
  change moved to `openspec/changes/archive/2026-07-02-themis-core-model/`.
- **Delta specs synced into the main specs** (`openspec/specs/`): a new `artifact-registration`
  capability, plus updates to `cve-triage`, `sbom-ingestion`, `sbom-management`, and `sbom-store`
  (totals: +9 requirements added, ~10 modified). All 18 specs validate.
- **Status/context docs refreshed to v0.3.9.** `openspec/STATUS.md` (release-tags table + roadmap
  through v0.3.9; core-model moved Active → Completed), `PROJECT_CONTEXT.md` (v0.3.x maintenance
  line marked complete), and `project-backlog.md` (release list + a new **Architecture — deep-module
  deepening opportunities** section, AD-1…AD-4, tracking the architecture-review findings).

## Release-tag reality (for reference)

`v0.3.0, v0.3.2, v0.3.3, v0.3.4, v0.3.5, v0.3.6, v0.3.7, v0.3.8, v0.3.9` — then this `v0.3.10`.
There is **no `v0.3.1`** (the line went `v0.3.0 → v0.3.2`).

## Upgrade

Nothing to deploy — documentation and OpenSpec only. No binary, schema, or config change.
