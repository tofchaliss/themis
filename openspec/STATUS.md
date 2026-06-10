# Themis — Project Status

_Maintained automatically by openspec skills (`propose`, `apply`, `archive`).
Last updated: 2026-06-10._

---

## Active Changes

| Change | Status | Started | Progress | Blocked On |
| --- | --- | --- | --- | --- |
| themis-phase-2 | Architecture Reference | 2026-06-09 | proposal ✓  design ✓  scenario ✓ | — (reference doc, not implemented) |
| themis-phase-2a | Planned | — | not started | Group 16 complete + v0.1.0 tagged |
| themis-phase-2b | Planned | — | not started | themis-phase-2a complete |
| themis-phase-2c | Planned | — | not started | themis-phase-2b complete + KB seeded |

## Prerequisite Work

- **Group 16 hardening (9 tasks open)** — gate before `themis-phase-2` implementation starts;
  must complete and tag `v0.1.0` first.
  Full detail: `openspec/changes/archive/2026-06-09-themis-phase-1/tasks.md` §16

  | # | Task | Status |
  | --- | --- | --- |
  | 16.1 | Normalise Alpine package names for OSV queries | Open |
  | 16.2 | Integration test: Alpine SBOM ingest | Open |
  | 16.3 | Integration test: rpm SBOM | Open |
  | 16.4 | `POST /api/v1/products/{id}/images` — image registration endpoint | Open |
  | 16.5 | Upload helper script | Open |
  | 16.6 | `make check` passes clean | Open |
  | 16.7 | `adapter/store/` coverage ≥ 90% | Open |
  | 16.8 | `adapter/osv/` coverage ≥ 90% | Open |
  | 16.9 | Merge to `main`, tag `v0.1.0` | Open |

## Completed Changes

| Change | Archived | Delivered |
| --- | --- | --- |
| themis-phase-1 | 2026-06-09 | artifact-trust, sbom-parser, sbom-ingestion, sbom-store, intelligence-enrichment, cve-triage, cve-watch, notification-service |

---

## Phase Roadmap

| Phase | Change | Theme | State |
| --- | --- | --- | --- |
| Phase 1 | themis-phase-1 | Core intelligence platform — Go REST API + PostgreSQL | Complete (archived 2026-06-09) |
| Phase 2a | themis-phase-2a | Signal Foundation — feeds, graph entities, VEX export | Planned |
| Phase 2b | themis-phase-2b | AI Intelligence — workers, RAG, pgvector | Planned |
| Phase 2c | themis-phase-2c | AI-Assisted VEX — auto-apply, FP, thresholds | Planned |
| Phase 3 | themis-phase-3 | Production platform — Docker, UI, Redis, RBAC, cosign | Not started |

Architecture reference for Phases 2a–2c: `openspec/changes/themis-phase-2/`
