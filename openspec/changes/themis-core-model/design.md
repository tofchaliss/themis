## Context

Phase 1 + 2a store both artifact composition and temporal scan results in a single
`sbom_documents` table, with `risk_context` keyed off `component_vulnerability_id` (a per-scan
row). The target model and entity hierarchy are already decided (see
`project-backlog.md` §HIGHEST PRIORITY — Core Data Model Restructure; Q1/Q2 confirmed). What
this design fixes is the *execution*: the migration strategy and the precise table/PK/FK
moves, so the work can be implemented without ambiguity.

The migration runner is `golang-migrate` (append-only, version-tracked). Migrations 000001–000019
exist; 000001–000004 define the base tables this change reshapes. Release tags are `v0.1.0` and
`v0.2.0` — both pre-1.0, no production deployment whose data must survive.

Target hierarchy:

```text
product
  └── project  (product_id)                 ← unchanged; default project auto-created
        └── version  (project_id NOT NULL)   ← was: version.product_id
              └── artifact  (version_id,      ← merges artifacts + images
                              image_digest TEXT UNIQUE)
                    ├── sbom        (artifact_id)            1 per artifact (composition)
                    │     ├── component_versions       (sbom_id)
                    │     └── dependency_relationships  (sbom_id)
                    └── scan_report (artifact_id, scanner)   N per artifact (temporal)
                          └── component_vulnerabilities (scan_report_id)
                                └── risk_context  PK (artifact_id, component_purl, cve_id)
```

## Goals / Non-Goals

**Goals:**

- Split composition (`sboms`) from temporal scans (`scan_reports`); 1 sbom + N scan reports
  per artifact.
- Make triage durable across rescans via an identity-based `risk_context` PK.
- Merge `artifacts` + `images`; make `image_digest` the global artifact identity.
- Re-parent `versions` under `projects`; auto-create a default project on product registration.
- Remove `is_latest` / `supersedes_id`; derive "latest" from `scanned_at`.
- Land schema-only, ahead of Phase 2b, with all Phase 2a intelligence behaviour preserved.

**Non-Goals:**

- **No data migration / no backfill.** Existing dev databases are dropped and re-initialised.
- No Phase 2b AI work, no pgvector, no new intelligence logic.
- No change to Phase 2a algorithms (EPSS/KEV, ExploitDB, Layer 1/2, VEX matching/export) — FK
  traversal only.
- No new scanner integrations; `scan_reports.scanner` is a label, not a new ingestion path.
- **No per-customer triage scope.** Triage decisions stay artifact-global (D8); per-customer
  risk acceptance is deferred to Phase 2c and would be a separate change that widens the
  `risk_context` identity or adds an exception table.
- **No in-place data upgrade.** Greenfield squash baseline (D13); existing databases are
  re-initialised, not migrated.

## Decisions

### D1 — Greenfield migration: no backfill (structure refined by D13)

No forward data-migration is authored; the new schema is created directly. A fresh
`make migrate-up` on an empty database yields the `v0.3.0` schema. **The migration is structured
as a squashed baseline with a schema-skew guard — see D13** (which supersedes the earlier
"rewrite 000001–000004 in place" framing because patch-in-place is unsafe across an
inter-referencing chain).

- **Why:** no install needs to survive (pre-1.0; README already documents drop-and-recreate
  for local dev). Append-only discipline buys nothing when no database is carried across, and a
  forward-migration + `risk_context` backfill would be the single largest and riskiest part of
  the change for zero benefit.
- **Alternative considered:** additive `000020+` migrations that create the new tables, backfill
  from `sbom_documents`, then drop the old ones. Rejected — large backfill surface (including an
  undefined triage-collision rule when two old scans carried different decisions on the same
  `(purl, cve_id)`), transitional nullable columns, all to preserve data we have decided not to
  preserve.
- **Operator impact:** upgrading a populated `v0.2.0` database is *not* supported; the documented
  path is `dropdb && createdb && make migrate-up` (already in README §Full database reset).

### D2 — `sboms` (composition) vs `scan_reports` (temporal)

`sboms` holds an uploaded composition (raw SBOM document + component inventory). `scan_reports`
holds one correlation run's findings at a point in time. `component_versions` and
`dependency_relationships` hang off `sboms`; `component_vulnerabilities` hang off `scan_reports`.
`scan_reports` carries both `sbom_id` (the composition it scanned) and a denormalized
`artifact_id` (for fast artifact-scoped queries).

- **Why split:** the uploaded composition is re-correlated over time — a "rescan" is
  re-running correlation against the *same* uploaded SBOM as the CVE database evolves, with **no
  new upload**. That temporal axis is `scan_reports`; the upload is `sboms`.
- **Composition is NOT keyed on `artifact_id` alone (refines backlog "1 sbom per artifact").**
  See D9 — it is keyed on `(artifact_id, sbom_checksum)`, because composition is itself a tool
  output and different tools/corrected uploads produce different inventories for the same digest.
- **Latest scan:** `scan_reports WHERE artifact_id = $1 ORDER BY scanned_at DESC LIMIT 1`. No
  `is_latest` column, no `supersedes_id` chain. The "current findings" invariant is D10.
- **Idempotency:** identical re-submissions do not create phantom scans — see D12.

### D3 — `risk_context` keyed on `(artifact_id, component_purl, cve_id)`

The triage identity is "for CVE-X in component PURL running in this artifact, we accept the
risk" — invariant across rescans. PK becomes `(artifact_id, component_purl, cve_id)`, where
`component_purl` is the **version-qualified** PURL (see D11).

- **Why:** removes the per-scan coupling that orphaned decisions on every rescan.
- **Identity is denormalized onto the finding (D11).** `component_vulnerabilities` today stores
  only `component_version_id` + `vulnerability_id` — neither the PURL nor the CVE id — and
  `components.purl` is *versionless*. So the finding row MUST carry a denormalized
  version-qualified `component_purl` and `cve_id`, or the identity key cannot be formed without
  fragile multi-table joins and would collapse component versions. See D11.
- **Alternative considered:** keep `component_vulnerability_id` PK and re-link old `risk_context`
  on each rescan. Rejected — re-link logic is exactly the silent-loss bug surface; identity PK
  removes the class of bug instead of patching it.
- **Scope:** persists across *rescans* of the same digest. Cross-*rebuild* (new digest)
  persistence is the `themis_generated` VEX overlay's job — see D14.
- **No backfill (per D1):** the new PK applies to all data created from `v0.3.0` onward.

### D4 — Merge `artifacts` + `images`; `image_digest` globally UNIQUE

One `artifacts` table carries `version_id`, `artifact_type`, and `image_digest TEXT UNIQUE`.
Same digest = same physical content = same artifact, belonging to exactly one version. The
separate `images` table is dropped.

- **Why:** the join table added no value; a global digest UNIQUE constraint is the natural
  identity and removes the `image_id` indirection from the upload path.

### D5 — `versions.project_id NOT NULL`; auto-create default project

`product_versions` becomes `versions` with `project_id NOT NULL` (replacing `product_id`).
Product registration auto-creates a default project, so a product always has a project to
parent its versions without a manual call.

- **Why:** a version always has a project parent (Q1 confirmed); the auto-default keeps the
  single-project common case a one-step product create.

### D6 — Registration endpoints replace manual SQL

`POST /api/v1/products/{id}/artifacts` (register an artifact under the product's default/specified
version) and `POST /api/v1/projects/{id}/versions` (create a version under a project) replace the
README's `INSERT INTO images/artifacts` workaround (Group 16.4 / 16.10).

- **Why here:** this change redefines both tables; the endpoints must speak the new shape.

### D7 — `scan_reports` immutability & layer placement

`scan_reports` (and the `component_vulnerabilities` hanging off it) are **Layer 1 immutable
facts**, same append-only discipline as `sboms`/`components`/`vulnerabilities`. The split from
`sboms` is about **stability vs. temporality**, not mutability: `sboms` is one stable row per
artifact ("what is installed"); `scan_reports` is N frozen rows per artifact ("what scanner S
found at time T"). A scan report is never updated once written.

All mutable state — `effective_state`, EPSS/KEV enrichment, triage — lives in `risk_context`
(Layer 2), keyed on `(artifact_id, component_purl, cve_id)`. This is the reason for that key
(D3): it lifts every mutable concern out of the immutable scan record so the scan stays a
frozen historical fact while "what we currently think about this CVE in this artifact" floats
above individual scans and survives across them.

Lifecycle of a `scan_report`:

| Operation | Allowed? |
| --------- | -------- |
| INSERT (new scan) | yes — always appends |
| UPDATE content (findings, `scanned_at`) | no — immutable fact |
| Soft-delete (`deleted_at` tombstone) | yes — via `DELETE /api/v1/sboms/{id}`, audit-logged |
| Hard delete via API | no |

- **Why:** re-correlation / EPSS-KEV refresh / VEX overlay must NOT mutate a past scan. They
  either append a new `scan_report` (a fresh scan) or update `risk_context` (Layer 2). An
  implementer must never add an `UPDATE scan_reports SET ...` on the re-enrichment path.
- **Soft-delete is a tombstone, not a mutation** of recorded facts — consistent with the
  existing `sbom_documents` soft-delete semantics carried into `sbom-management`.
- **Alternative considered:** put mutable enrichment columns (`effective_state`, EPSS/KEV) on
  the scan row. Rejected — it re-couples mutable intelligence to a per-scan row, reintroducing
  the silent-triage-loss class of bug that D3 exists to remove.

### D8 — Customer affiliation is derived context for triage, not a triage-decision dimension

A finding's affected customers are **derived through the asset graph**
(`artifact → version → project → product → microservices → deployments → customers`), never
denormalized onto `scan_reports`/`risk_context`. "Multiple vs individual customer" is simply
`COUNT(DISTINCT customer)` — already computed by Phase 2a blast-radius and persisted as
`risk_context.blast_radius_score`. Core-model changes only the FK path used to resolve it.

Triage **surfaces** this derived set as context (affected-customer count + IDs + environments),
but the triage **decision stays keyed on `(artifact_id, component_purl, cve_id)`** — one verdict
per finding identity, applying to every customer/deployment of the artifact.

- **Why:** a vulnerability and its "false positive / not reachable / accepted" verdict are
  properties of the artifact's *code* — same `image_digest`, same verdict everywhere. The
  customer dimension is *exposure*, which belongs on the read/prioritisation side (blast radius,
  routing, notification) that Phase 2a already wires — not in the decision identity.
- **Why not denormalize onto the scan:** deployment topology changes independently of scans;
  copied customer IDs would go stale. Derive-and-JOIN keeps a single source of truth.
- **Alternative considered (deferred):** per-customer triage scope (accept for an internal
  customer, keep open for an external one). Requires widening the `risk_context` identity with
  `customer_id` or a separate exception table — a Phase 2c topic (Non-Goal below).

### D9 — Composition is keyed `(artifact_id, sbom_checksum)`, not 1-per-artifact (resolves H1, H8)

A `sboms` row is one *distinct uploaded SBOM* for an artifact: keyed `(artifact_id,
sbom_checksum)`, append-only. Most artifacts have exactly one; a different SBOM tool/format, or a
corrected re-upload, yields an additional `sboms` row. A `scan_report` references the specific
`sbom_id` it correlated.

- **Why this refines the backlog ("1 sbom per artifact"):** composition is itself a *tool
  output*, not a physical invariant. Syft-CycloneDX and Trivy-JSON of the *same* digest emit
  different component lists and PURLs. A hard 1-per-artifact rule would either drop the second
  tool's inventory (orphaning its findings, which reference component_versions absent from the
  canonical sbom) or force composition to be wrong. Keying on content removes the conflict.
- **Resolves H8 (poisoned digest):** a bad first SBOM is no longer permanent — upload a corrected
  SBOM (new checksum → new `sboms` row); subsequent scans correlate against it. No mutation of the
  immutable prior row.
- **Common case unchanged:** one tool, one upload ⇒ one `sboms` row per artifact.
- **Confirmed 2026-06-18 — supersedes the backlog.** The backlog §Core Data Model lists
  `sbom (artifact_id) 1 per artifact`; this change deliberately replaces it with `(artifact_id,
  sbom_checksum)`. The rejected alternative was hard single-tool enforcement (reject divergent
  re-uploads) — declined because it cannot correct a bad first SBOM and drops multi-tool
  inventories.

### D10 — "Current findings" is an explicit invariant + one shared latest-scan filter (resolves H2)

After the split, every ingest appends a full set of `component_vulnerabilities` under a new
`scan_report`, so a rescanned artifact holds N× finding rows (one set per scan). "Current
findings" SHALL be exactly the `component_vulnerabilities` whose `scan_report_id` is the latest
`scan_reports` row for the artifact. Every read path (status counts, SBOM/scan listing, VEX
export, blast-radius, scan detail) MUST apply this filter through **one shared helper / SQL
view** (e.g. `v_latest_findings`), never an ad-hoc per-query join.

- **Why:** without a single enforced filter, any count query silently returns N× the
  vulnerabilities — a regression that does not error, only misreports. Centralizing it makes the
  invariant testable and auditable.
- **Task impact:** audit all ~10 store read paths against the shared filter.

### D11 — Denormalize version-qualified `component_purl` + `cve_id` onto the finding (resolves H3)

`component_vulnerabilities` SHALL carry a denormalized `component_purl` (the **version-qualified**
PURL, e.g. `pkg:apk/busybox@1.36`, reconstructed from `components.purl` +
`component_versions.version`) and `cve_id`, written at correlation time. `risk_context` is keyed
and joined on these.

- **Why version-qualified:** `components.purl` is versionless; the backlog's own triage example
  (`pkg:apk/busybox@1.36`) is otherwise inexpressible, and a versionless key would collapse two
  installed versions of the same package (busybox 1.35 in the base layer, 1.36 in the app layer)
  into a single triage decision. Version-qualified keeps triage precise.
- **Why denormalize:** avoids a fragile two-hop join (`component_versions → components`,
  `vulnerabilities`) on every triage read/write and makes the identity self-contained on the row.
- **Alternative considered:** versionless purl in the key. Rejected — silently over-suppresses.

### D12 — Ingestion idempotency: dedup scans, do not append phantoms (resolves H4)

`scan_reports` SHALL NOT append on an idempotent re-submission. A re-ingest whose
`(sbom_id, scan_checksum)` matches a recent scan (and any honored `Idempotency-Key`) SHALL return
the existing `scan_report` rather than creating a duplicate. Only a genuinely new correlation run
(new content, or a deliberate re-scan) appends a `scan_report`.

- **Why:** the prior model's `UNIQUE(image_digest, checksum_sha256)` guarded against retry /
  at-least-once queue redelivery. "Scans always append" would re-introduce duplicate scans on
  every network retry, re-running correlation and inflating history. Idempotency is not optional.

### D13 — Migration is a squashed greenfield baseline with a loud schema-skew guard (resolves H5, H6; sharpens D1)

Rather than patch FK references across 19 inter-referencing migrations in place, **consolidate to
a single squashed baseline** that defines the `v0.3.0` schema directly; retire the old migration
bodies. Additionally, add a **startup schema-shape assertion** (or migration-baseline version gap)
so a database that was not re-initialised fails **loudly and actionably**.

- **Why squash, not patch (H6):** rewriting `000002` to create `scan_reports` while `000010` /
  `000016` still reference `component_vulnerability_id` leaves the chain internally inconsistent —
  a clean `migrate-up` from zero breaks midway. A squashed baseline is coherent by construction.
- **Why the guard (H5):** `golang-migrate` tracks the applied *version number*, not content. A dev
  or CI database already at version 19 sees "nothing to run" against rewritten migrations and ends
  up running the **new binary on the old schema** — runtime errors that look nothing like a
  migration failure. The guard converts that into one clear "re-initialise your database" error.
- **Operator/dev impact:** existing databases (dev, CI volumes, test fixtures) MUST be dropped and
  recreated; there is no in-place upgrade. Documented in README + startup log.
- **This sharpens D1** — D1 said "rewrite 000001–000004"; D13 makes it a squash-to-baseline plus a
  skew guard, because patch-in-place is unsafe across an inter-referencing chain.

### D14 — Two triage-persistence scopes: `risk_context` (rescan) vs `themis_generated` VEX (rebuild) (resolves H7)

`risk_context` triage persists across **rescans of the same digest** (same `artifact_id`). A
**rebuild** produces a new digest = new `artifact_id`, so artifact-scoped triage does not carry
over — cross-build persistence is provided by the `themis_generated` VEX overlay, keyed on
`(component_purl, cve_id)` and re-applied during enrichment of any future artifact.

- **Precedence on a new artifact:** the existing VEX precedence holds — `themis_generated` >
  `manual`/`vendor` > `ai_generated` > `upstream_vendor`. An inherited `themis_generated` VEX
  applies via overlay; a fresh artifact-scoped triage on the new artifact can override it.
- **Why document this:** users expect "I triaged this last build" to persist; for a rebuild that
  is the VEX overlay's job, not `risk_context`. Stating both mechanisms and their scopes prevents
  "triage looks lost" confusion.

## Risks / Trade-offs

- **Wide rename surface (~23 non-test + ~23 test files)** → mechanical FK column/table renames;
  isolate the genuinely behavioural edits (ingestion split, `risk_context` PK, latest-scan
  query) from the rename churn so review can separate them. `make clean-arch` + the full gate
  suite guard regressions.
- **Silent schema-skew on un-dropped DBs (H5)** → `golang-migrate` runs nothing against a DB
  already at the old version; new binary on old schema fails obscurely. Mitigated by the squash
  baseline + startup schema-shape guard (D13) that fails loudly with "re-initialise your database".
- **N× finding double-count after the split (H2)** → every count/list path must filter to the
  latest `scan_report`; a missed filter misreports rather than errors. Mitigated by the single
  shared latest-scan helper/view and a read-path audit (D10).
- **Composition divergence across SBOM tools (H1)** → different tools emit different inventories
  for one digest; a hard 1-per-artifact rule orphans findings. Mitigated by keying `sboms` on
  `(artifact_id, sbom_checksum)` (D9; confirmed — supersedes the backlog's 1-per-artifact).
- **`risk_context` identity ambiguity (H3)** → finding rows carry neither purl nor cve_id and
  `components.purl` is versionless; a versionless key over-suppresses across versions. Mitigated
  by denormalizing the version-qualified `component_purl` + `cve_id` onto the finding (D11).
- **Non-idempotent ingest creates phantom scans (H4)** → retries/redelivery would append
  duplicate scans. Mitigated by scan dedup on `(sbom_id, scan_checksum)` + Idempotency-Key (D12).
- **Wide rename surface (~23 non-test + ~23 test files)** → mechanical FK column/table renames;
  isolate the genuinely behavioural edits (ingestion split, `risk_context` PK, latest-scan
  query) from the rename churn so review can separate them. `make clean-arch` + the full gate
  suite guard regressions.
- **Phase 2a regressions from FK re-pointing** → the AC-16..24 + Phase 1 acceptance suites run
  unchanged against the new schema; any behavioural drift surfaces there.
- **Scope creep into Phase 2b** → strictly schema-only; `scan_reports.scanner` is a label, not a
  new scanner pipeline.

## Migration Plan

1. **Squash to a greenfield baseline (D13)** — replace the 000001–000019 chain with a coherent
   `v0.3.0` baseline defining: `products`, `projects`, `versions` (`project_id NOT NULL`), merged
   `artifacts` (unique `image_digest`), `sboms` (`(artifact_id, sbom_checksum)`), `scan_reports`
   (`sbom_id`, denormalized `artifact_id`, `scanner`, `scanned_at`, `scan_checksum`),
   `component_vulnerabilities` (denormalized `component_purl`, `cve_id`; FK `scan_report_id`),
   `risk_context` (PK `(artifact_id, component_purl, cve_id)`), and the surviving Phase 2a tables
   unchanged. No `is_latest`/`supersedes_id`.
2. **Add the schema-skew guard (D13)** — startup assertion / baseline version gap so an
   un-reinitialised DB fails loudly with an actionable message.
3. Propagate domain type + store-query renames; add the shared latest-scan filter/view (D10);
   split the ingestion insert (one `sboms` per `(artifact_id, sbom_checksum)` + one `scan_reports`
   per genuine correlation, idempotent per D12); write denormalized purl/cve at correlation (D11);
   update `risk_context` upsert to the identity key.
4. Add registration endpoints + auto-default-project.
5. Update tests/fixtures; add the triage-survives-rescan, latest-scan-count, multi-tool-sbom, and
   registration integration tests.
6. Update README/PROJECT_CONTEXT data-model docs, reset flow, and the "re-initialise your DB" note.
7. **Rollback:** redeploy the previous binary against a re-initialised database (no in-place
   downgrade; greenfield by design).

## Open Questions

- **(Resolved by D12)** ~~Should `scan_reports` carry a `dedup_checksum`?~~ Yes — scans dedup on
  `(sbom_id, scan_checksum)`; identical re-submissions return the existing scan, only genuine
  re-correlations append.
- **(Resolved by D9, confirmed 2026-06-18)** ~~Is `sboms` strictly one-per-artifact?~~ No — keyed
  `(artifact_id, sbom_checksum)`; one in the common single-tool case, N for multi-tool/corrected
  uploads. Supersedes the backlog's "1 per artifact".
- Auto-created default project naming/slug convention (e.g. `default` vs product-name-derived) —
  finalise during implementation; no external contract depends on it.
- Exact form of the schema-skew guard (D13): startup table/column assertion vs a migrate baseline
  version bump — decide during implementation; both satisfy the "fail loudly" requirement.
