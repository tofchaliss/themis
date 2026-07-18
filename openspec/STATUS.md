# Themis — Project Status

_Maintained automatically by openspec skills (`propose`, `apply`, `archive`).
Last updated: 2026-07-18 (**Phase-3 greenfield pivot** — the DDD bounded-context rebuild, per the
architecture book `docs/architecture/` Books I–III + the 69 ADRs `docs/adr/`, is the **sole go-forward**;
the current architecture is **frozen at v0.3.x**. `themis-ai-1` and `themis-phase-2` archived as
superseded. **Grilling phase complete: all six context EDRs done** (`docs/engineering/decisions/`), and
**all six OpenSpec changes scaffolded** — `phase3-shared-kernel` (M2), `phase3-evidence` (M6),
`phase3-knowledge` (M7), `phase3-governance` (M8), `phase3-communication` (M9), `phase3-intelligence` (M4).
Implementation next, in dependency order. See `docs/engineering/PHASE3-STATUS.md`.)_

---

## Active Changes

| Change | Status | Started | Progress | Blocked On |
| --- | --- | --- | --- | --- |
| **phase3-shared-kernel** (M2) | **Implemented — 20/20 tasks, gated** (branch `phase3-evidence`, uncommitted) | 2026-07-16 | `internal/kernel/{value,id,event}` + `internal/registry/{domain,app,adapters}` + `cmd/registry`; `make check` green — value/id/event + registry domain/app 100%, registry store 89.2%, http 92.7%; `ReleaseExists` backs Evidence's `SubjectRef` | — |
| **phase3-evidence** (M6) | **Implemented — 7/7 groups, gated** (branch `phase3-evidence`, uncommitted) | 2026-07-15 | full context (`internal/evidence` + `internal/kernel/value` + `cmd/evidence`); tests green, coverage 100% (domain/app/parser/trust/subjectref) · store 84.5% · http 95.7%; blueprints 01–06 written | SubjectRef still uses the stub; `phase3-shared-kernel` now provides `registry.ReleaseExists` — swapping the stub for a registry-backed adapter is the remaining wiring step |
| **phase3-knowledge** (M7) | **Implemented — 25/25 tasks, gated** (branch `phase3-evidence`, uncommitted) | 2026-07-16 | full context `internal/knowledge/{domain,app,adapters}` (Faultline aggregate + deterministic reconciliation [rapid property], 6 feed ACLs, Postgres aggregate + outbox, correlation via Evidence read-API client + `ComponentMatched`, watch/discovery ports, read API + reconciler); domain/app 100%, adapters 83–98% | feed-fetch HTTP clients are ports awaiting real OSV/NVD adapters |
| **phase3-governance** (M8) | **Implemented — 24/24 tasks, gated** (branch `phase3-evidence`, uncommitted) | 2026-07-17 | full context `internal/governance/{domain,app,adapters}` + `cmd/governance` (Finding aggregate + reopenable lifecycle + append-only Position versions + Governance Proposals [rapid property], inbound Knowledge seam consumer → find-or-create Finding / auto-raise proposal [never auto-decide], authority line + policy auto-accept, Postgres aggregate + outbox + projections + relay, spec-first triage/read API, reconciler); domain/app/inbound 100%, store 80.5%, http 97.9% | Communication consumes `PositionEstablished`/`PositionRevised` (next: M9) |
| **phase3-communication** (M9) | **Implemented — 22/22 tasks, gated** (branch `phase3-evidence`, uncommitted) | 2026-07-18 | full context `internal/communication/{domain,app,adapters}` + `cmd/communication` (Publication aggregate [immutable content + mutable delivery status + append-and-supersede, capped/regenerable payload], deterministic materialization with the **stance-equality invariant**, 6-serializer registry [OpenVEX/CycloneDX-VEX/CSAF/markdown/json-report/text], inbound Governance Position-event consumer → publishable-positions queue [Positions only, no auto-publish], human-triggered `CreatePublication` + supersede, Postgres aggregate + outbox + projections + relay, delivery worker [exactly-once off pending status] + retention/pruning + reconciler, spec-first publish/read/preview API); domain/app 100%, adapters 81–100% | terminal — **pipeline complete** (Evidence→Knowledge→Governance→Communication) |
| **phase3-intelligence** (M4) | **Δ1 Implemented — 37/37 tasks, gated** (branch `phase3-evidence`, uncommitted) | 2026-07-18 | `EDR-INTELLIGENCE-01` Rev 2 (D1–D13); the reactive walking skeleton — `internal/intelligence/{domain,app,adapters}` + `cmd/intelligence` (stateless) + Governance caller seam (`adapters/intelligence` client + no-op + on-demand `POST /findings/{id}/recommend`); `recommend_position` affected/not-affected triage, Ollama (OpenAI-compat) + fake provider, 3-stage validation, disable gate (D13); `make check` green. Δ2–Δ4 (typed dispatch/admission, Python+RAG, autonomy+LLMOps) remain | — |
| Layer-0 refactor (CR-1…CR-10) | **Released (v0.3.0, 2026-06-24)** | 2026-06-23 | all 10 CRs merged and tagged `v0.3.0`; all gates green. Closes D-CVSS-1, D-FEED-1, D-NVD-1, D-LOG-1. See `project-backlog.md`. | — (current arch frozen at v0.3.x) |
| ~~themis-phase-2~~ | **Archived — superseded** (2026-07-14) | — | superseded by `docs/architecture/` + `docs/adr/`; reference input for Phase-3 grilling | archived → `changes/archive/2026-07-14-themis-phase-2/` |
| ~~themis-ai-1~~ | **Archived — superseded** (2026-07-14) | — | never built; AI design folded into Phase-3 Intelligence (M4, INT ADRs) | archived → `changes/archive/2026-07-14-themis-ai-1/` |
| ~~themis-phase-2b / 2c~~ | **Superseded by greenfield** | — | 2b folded into `themis-ai-1` (archived); 2c → Phase-3 Governance/Intelligence roadmap | — |

## Prerequisite Work

- **`themis-core-model` restructure — ✅ DONE (released v0.3.0; archived 2026-07-02).** Split
  `sbom_documents` into `sboms` + `scan_reports`; `risk_context` identity PK; removed
  `is_latest`/`supersedes_id`; merged `artifacts`+`images`; `version.project_id` FK; Group 16
  registration endpoints. 58/58 tasks; delta specs synced to `openspec/specs/`. Archived at
  `openspec/changes/archive/2026-07-02-themis-core-model/`. No longer gates Phase 2b (unblocked).

> Group 31 and the Group 16 hardening remainder shipped in **`themis-v0-2-1`** (archived
> 2026-06-17, 36/37 tasks; only the manual merge-to-`main` + tag `v0.2.1` step, 7.7, remains).

- **Group 16 hardening remainder (targets v0.2.1)** — the original "gate before tagging `v0.1.0`"
  framing is retired: `v0.1.0` was tagged retroactively on the Phase 1 commit (2026-06-17,
  replacing `themis-phase-1`). The hardening tasks now ship in the `v0.2.1` maintenance release;
  the two registration endpoints moved under `themis-core-model`.
  Full detail: `openspec/changes/archive/2026-06-09-themis-phase-1/tasks.md` §16

  | # | Task | Status |
  | --- | --- | --- |
  | 16.1 | Normalise Alpine package names for OSV queries | **Done** (v0.2.1) |
  | 16.2 | Integration test: Alpine SBOM ingest | **Done** (`TestV021AlpineSBOMOSVCorrelation`) |
  | 16.3 | Integration test: rpm SBOM | **Done** (`TestV021RPMSBOMIngestSkipsUnsupportedOSV`) |
  | 16.4 | Artifact registration endpoint | Moved → `themis-core-model` |
  | 16.5 | Upload helper script | **Done** (`scripts/upload-sbom.sh`, `scripts/alpine-e2e-gate.sh`) |
  | 16.6 | `make check` passes clean | **Done** (v0.2.1) |
  | 16.7 | `adapter/store/` coverage ≥ 90% | **Done** (91.6%) |
  | 16.8 | `adapter/osv/` coverage ≥ 90% | **Done** (93.6%) |
  | 16.9 | Tag `v0.1.0` + Phase 1 release notes | **Done** (retroactive tag) |
  | 16.10 | Version registration endpoint | Moved → `themis-core-model` |

- **Group 31 — Feed reliability and signal-quality (8 tasks complete on branch; targets v0.2.1)** —
  completed in `themis-v0-2-1`; these fixes remain a Phase 2b prerequisite until
  `v0.2.1` is merged/tagged from `themis-phase-2`.
  All originated from Phase 2a runtime failures found during live Alpine SBOM bring-up.
  Full detail: `openspec/changes/archive/2026-06-17-themis-phase-2a/tasks.md` §31.

  | # | Task | Status |
  | --- | --- | --- |
  | 31.1 | Normalize `ALPINE-CVE-*` IDs to `CVE-*` in `mapOSVVuln` | **Done** (v0.2.1) |
  | 31.2 | Fix `ParseOSVFeed.firstCVE()` Alpine prefix strip | **Done** (v0.2.1) |
  | 31.3 | Fix OSV CVSS vector parsing (`fmt.Sscanf` bug) | **Done** (v0.2.1) |
  | 31.4 | Alpine OSV URL fix — HTTP 302 → GCS zip | **Done** (v0.2.1) |
  | 31.5 | Rocky Linux OSV URL fix — HTTP 404 → GCS zip | **Done** (v0.2.1) |
  | 31.6 | Red Hat CSAF — implement `CSAFDirectoryFeedSource` | **Done** (v0.2.1) |
  | 31.7 | Expose `exploit_public` in scan findings API | **Done** (v0.2.1) |
  | 31.8 | Wire `themis_exploitdb_sync_total` Prometheus counter | **Done** (v0.2.1) |

## Completed Changes

| Change | Archived | Delivered |
| --- | --- | --- |
| themis-core-model | 2026-07-02 | Core data-model restructure (breaking, v0.3.0): `sboms` + `scan_reports` split, merged `artifacts` (unique `image_digest`), `versions.project_id`, `risk_context` identity PK `(artifact_id, component_purl, cve_id)` + Durable-Enrichment Identity Contract (D15), `v_latest_findings` view, schema-skew guard, artifact/version registration endpoints. 58/58 tasks; delta specs (artifact-registration, cve-triage, sbom-ingestion, sbom-management, sbom-store) synced to main specs |
| themis-v0-2-1 | 2026-06-17 | Alpine signal reliability: canonical CVE-ID normalization (`domain.NormalizeCVEID`), OSV CVSS vector parsing, Alpine package-name normalization, `ZipOSVFeedSource` + `CSAFDirectoryFeedSource` vendor feeds, `exploit_public`/enrichment on findings API, `themis_exploitdb_sync_total` metric, component-mismatch correlation logging, Group 31 + Group 16 remainder; 9 spec requirements synced. Merge/tag `v0.2.1` (7.7) still manual |
| themis-phase-2a | 2026-06-17 | EPSS/KEV sync, ExploitDB CSV, Layer 1 rules, asset graph, blast-radius, composite risk score V2, upstream vendor VEX (RHEL/Alpine/Rocky/Wolfi), VEX export, system status API, SBOM management, error UX, AC-16..AC-24, FR1–FR8; v0.2.0 merged to main (PR #16) |
| themis-phase-1 | 2026-06-09 | artifact-trust, sbom-parser, sbom-ingestion, sbom-store, intelligence-enrichment, cve-triage, cve-watch, notification-service; v0.1.0 (retroactive tag on Phase 1 commit, 2026-06-17) |

---

## Release tags

| Tag | Commit | Marks |
| --- | --- | --- |
| `v0.1.0` | `a94f3ba` (PR #10) | Phase 1 core platform — tagged retroactively 2026-06-17 (replaced `themis-phase-1`) |
| `v0.2.0` | `d02883c` (PR #15) | Phase 2a Signal Foundation |
| `v0.2.1` | `5e77d2b` | Maintenance: Group 31 feed fixes + Group 16 hardening remainder |
| `v0.3.0` | `469dd8c` (2026-06-24) | `themis-core-model` (breaking) + Layer-0 Correctness & Observability refactor (CR-1…CR-10) |
| `v0.3.2` | `4feae12` | Correlation correctness (canonical CVE-ID keying + el8/el9 release-stream scoping) + feeder resilience |
| `v0.3.3` | `711b0ac` | Distro-authoritative correlation identity + NVD by-CVE backfill robustness + `fixed_version`/`installed_version` on findings API |
| `v0.3.4` | `7e6c077` | Preserve backfilled CVSS in the catalog upsert (no clobber to `unknown`/0 on re-correlation) |
| `v0.3.5` | `62e0acc` (PR #38) | Red Hat VEX overlay via on-demand Security Data API (Option B) |
| `v0.3.6` | `e6b5faa` (PR #39) | Red Hat VEX minor-stream false-resolution fix (main-stream scoping + `epoch=` qualifier) |
| `v0.3.7` | `6fc334f` (PR #41) | OSV GIT-range over-match fix (skip GIT-type ranges; no commit-hash version bounds) |
| `v0.3.8` | `29943cf` (PR #42) | Scoped vulnerability-listing endpoints (product / project / version) |
| `v0.3.9` | `5d5ee3c` (PR #44) | Feed registry — user-defined `vexfeed.feeds` delta list |
| `v0.3.10` | `79bfb84` | Housekeeping — archive `themis-core-model`, sync delta specs into `openspec/specs/`, refresh status/context docs to v0.3.9 |
| `v0.3.11` | (PR #47) | Housekeeping — consolidate docs under `docs/` (release-notes / current-changes / architecture) + refresh stale context |
| `v0.4.0` | — (planned) | Phase 2b AI Intelligence |
| `v0.5.0` | — (planned) | Phase 2c AI-Assisted VEX |

## Phase Roadmap

| Phase | Change | Theme | State |
| --- | --- | --- | --- |
| Phase 1 | themis-phase-1 | Core intelligence platform — Go REST API + PostgreSQL | Complete (archived 2026-06-09; v0.1.0) |
| Phase 2a | themis-phase-2a | Signal Foundation — feeds, graph entities, VEX export | Complete (archived 2026-06-17; v0.2.0) |
| — | (maintenance) | v0.2.1 — feed reliability + Phase 1 hardening | Released (v0.2.1) |
| core-model + Layer-0 | themis-core-model + CR-1…CR-10 | Schema restructure (breaking) + correlation/feeder/observability refactor | **Released (v0.3.0, 2026-06-24)** |
| — | (maintenance) | v0.3.2–v0.3.9 — correlation/VEX correctness + ergonomics on the v0.3.0 schema (canonical CVE keying, el8/el9 streams, distro-authoritative identity, CVSS-clobber fix, Red Hat VEX overlay + minor-stream fix, OSV GIT-range fix, scoped vuln endpoints, feed registry) | **v0.3.2–v0.3.9 released** |
| Phase 2b | themis-phase-2b | AI Intelligence — workers, RAG, pgvector | Planned (unblocked) — targets v0.4.0 |
| Phase 2c | themis-phase-2c | AI-Assisted VEX — auto-apply, FP, thresholds | Planned — targets v0.5.0 |
| Phase 3 | themis-phase-3 | Production platform — Docker, UI, Redis, RBAC, cosign | Not started |

Architecture reference for Phases 2a–2c: `openspec/changes/themis-phase-2/`

Cross-phase intelligence source tier classification: `openspec/intel-source-tiers.md`

Canonical capability specs (source of truth, Phase 1 + 2a merged): `openspec/specs/`
(17 capabilities). Seeded 2026-06-17 when `themis-phase-2a` was archived with spec sync;
future changes update this tree via `openspec archive`.
