# Themis — Project Status

_Maintained automatically by openspec skills (`propose`, `apply`, `archive`).
Last updated: 2026-06-17._

---

## Active Changes

| Change | Status | Started | Progress | Blocked On |
| --- | --- | --- | --- | --- |
| themis-phase-2 | Architecture Reference | 2026-06-09 | proposal ✓  design ✓  scenario ✓ | — (reference doc, not implemented) |
| themis-phase-2b | Planned | — | not started | Group 31 (8 tasks) + `themis-core-model` |
| themis-phase-2c | Planned | — | not started | themis-phase-2b complete + KB seeded |

## Prerequisite Work

- **`themis-core-model` restructure (HIGHEST PRIORITY)** — must complete before any other open
  item. Splits `sbom_documents` into `sboms` + `scan_reports`; fixes silent triage loss; removes
  `is_latest` anti-pattern; adds `version.project_id` FK. Gates Group 16, Phase 2b, and all
  post-2a follow-ons. Full detail: `project-backlog.md` §Core Data Model Restructure.

- **Group 16 hardening remainder (targets v0.2.1)** — the original "gate before tagging `v0.1.0`"
  framing is retired: `v0.1.0` was tagged retroactively on the Phase 1 commit (2026-06-17,
  replacing `themis-phase-1`). The hardening tasks now ship in the `v0.2.1` maintenance release;
  the two registration endpoints moved under `themis-core-model`.
  Full detail: `openspec/changes/archive/2026-06-09-themis-phase-1/tasks.md` §16

  | # | Task | Status |
  | --- | --- | --- |
  | 16.1 | Normalise Alpine package names for OSV queries | Open → v0.2.1 |
  | 16.2 | Integration test: Alpine SBOM ingest | Open → v0.2.1 |
  | 16.3 | Integration test: rpm SBOM | Open → v0.2.1 |
  | 16.4 | Artifact registration endpoint | Moved → `themis-core-model` |
  | 16.5 | Upload helper script | Open → v0.2.1 |
  | 16.6 | `make check` passes clean | Open → v0.2.1 |
  | 16.7 | `adapter/store/` coverage ≥ 90% | Open → v0.2.1 |
  | 16.8 | `adapter/osv/` coverage ≥ 90% | Open → v0.2.1 |
  | 16.9 | Tag `v0.1.0` + Phase 1 release notes | **Done** (retroactive tag) |
  | 16.10 | Version registration endpoint | Moved → `themis-core-model` |

- **Group 31 — Feed reliability and signal-quality (8 tasks open; targets v0.2.1)** — must
  complete before Phase 2b begins. All are Phase 2a runtime failures found during live Alpine
  SBOM bring-up. Ships in the `v0.2.1` maintenance release alongside the Group 16 remainder.
  Full detail: `openspec/changes/archive/2026-06-17-themis-phase-2a/tasks.md` §31.

  | # | Task | Status |
  | --- | --- | --- |
  | 31.1 | Normalize `ALPINE-CVE-*` IDs to `CVE-*` in `mapOSVVuln` | Open |
  | 31.2 | Fix `ParseOSVFeed.firstCVE()` Alpine prefix strip | Open |
  | 31.3 | Fix OSV CVSS vector parsing (`fmt.Sscanf` bug) | Open |
  | 31.4 | Alpine OSV URL fix — HTTP 302 → GCS zip | Open |
  | 31.5 | Rocky Linux OSV URL fix — HTTP 404 → GCS zip | Open |
  | 31.6 | Red Hat CSAF — implement `CSAFDirectoryFeedSource` | Open |
  | 31.7 | Expose `exploit_public` in scan findings API | Open |
  | 31.8 | Wire `themis_exploitdb_sync_total` Prometheus counter | Open |

## Completed Changes

| Change | Archived | Delivered |
| --- | --- | --- |
| themis-phase-2a | 2026-06-17 | EPSS/KEV sync, ExploitDB CSV, Layer 1 rules, asset graph, blast-radius, composite risk score V2, upstream vendor VEX (RHEL/Alpine/Rocky/Wolfi), VEX export, system status API, SBOM management, error UX, AC-16..AC-24, FR1–FR8; v0.2.0 merged to main (PR #16) |
| themis-phase-1 | 2026-06-09 | artifact-trust, sbom-parser, sbom-ingestion, sbom-store, intelligence-enrichment, cve-triage, cve-watch, notification-service; v0.1.0 (retroactive tag on Phase 1 commit, 2026-06-17) |

---

## Release tags

| Tag | Commit | Marks |
| --- | --- | --- |
| `v0.1.0` | `a94f3ba` (PR #10) | Phase 1 core platform — tagged retroactively 2026-06-17 (replaced `themis-phase-1`) |
| `v0.2.0` | `d02883c` (PR #15) | Phase 2a Signal Foundation |
| `v0.2.1` | — (planned) | Maintenance: Group 31 feed fixes + Group 16 hardening remainder |
| `v0.3.0` | — (planned) | `themis-core-model` (breaking) + Phase 2b AI Intelligence |
| `v0.4.0` | — (planned) | Phase 2c AI-Assisted VEX |

## Phase Roadmap

| Phase | Change | Theme | State |
| --- | --- | --- | --- |
| Phase 1 | themis-phase-1 | Core intelligence platform — Go REST API + PostgreSQL | Complete (archived 2026-06-09; v0.1.0) |
| Phase 2a | themis-phase-2a | Signal Foundation — feeds, graph entities, VEX export | Complete (archived 2026-06-17; v0.2.0) |
| — | (maintenance) | v0.2.1 — feed reliability + Phase 1 hardening | Planned (Group 31 + Group 16 remainder) |
| Phase 2b | themis-phase-2b | AI Intelligence — workers, RAG, pgvector | Planned (blocked: Group 31 + core-model) |
| Phase 2c | themis-phase-2c | AI-Assisted VEX — auto-apply, FP, thresholds | Planned |
| Phase 3 | themis-phase-3 | Production platform — Docker, UI, Redis, RBAC, cosign | Not started |

Architecture reference for Phases 2a–2c: `openspec/changes/themis-phase-2/`

Cross-phase intelligence source tier classification: `openspec/intel-source-tiers.md`

Canonical capability specs (source of truth, Phase 1 + 2a merged): `openspec/specs/`
(17 capabilities). Seeded 2026-06-17 when `themis-phase-2a` was archived with spec sync;
future changes update this tree via `openspec archive`.
