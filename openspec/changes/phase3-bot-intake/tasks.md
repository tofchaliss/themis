# Tasks — phase3-bot-intake

Source of truth: `docs/engineering/decisions/EDR-INTAKE-01.md`, the **2026-10-12 amendment**
("Bot-friendly intake", decisions `B1`–`B6` and the status-code table). Design notes:
`design.md` in this directory.

**How to read this list.** Every step is sized to land and be verified **on its own** — one package,
one named test, one reason to fail. Steps are numbered and ordered; a later step may depend on an
earlier one, but no step needs a later one to be testable. Markers:

| marker | meaning |
| --- | --- |
| **[API]** | changes an OpenAPI spec → regenerate (`make generate-api-<ctx>`); handlers are generated, never hand-edited |
| **[SCHEMA]** | changes a stored shape (a column, a constraint, a stored enum) |
| **[MIGRATION]** | adds a migration file pair; **up/down reversibility is a task gate** |

Every group ends by making **`make vet-tags`** green (a tagged file is invisible to the default build
and rots silently) and **`make check`** green locally; CI runs `make check-ci`. This change carries
**no `specs/` deltas** — archive with `openspec archive phase3-bot-intake --skip-specs -y`.

---

## Group 0 — The reason enum, first, so no later step depends on a later one

- [x] **0.1 — [API] The four new reasons, everywhere at once.** `internal/evidence/domain/intake.go`
  gains `create_release_conflict` (400), `incomplete_release_triple` (400), `ambiguous_name` (422)
  and `build_id_invalid` (400) with their HTTP mapping; `api/evidence.openapi.yaml`'s `RejectReason`
  enum gains the same four (additive); regenerate with `make generate-api-evidence`; the dashboard's
  intake-reason table gains them too. Nothing produces them yet — they are vocabulary, landed whole,
  so 1.10 (`ambiguous_name`) and 2.4 (the parameter reasons) depend only on an EARLIER step and no
  production stub is needed.
  *Packages:* `internal/evidence/domain` (100% tier), `api`, `internal/evidence/adapters/http/gen`,
  `cmd/dashboard/static`.
  *Tests:* extend `TestIntakeReasonTaxonomyIsClosed` to the four; the existing spec-vs-Go enum
  contract assertion in `internal/evidence/adapters/http` must still pass (it fails if either side
  grows alone); `make js-check`.

---

## Group 1 — Registry: uniqueness at the database, idempotent creates, honest abstention (B4)

Lands and is useful on its own: two concurrent registrations stop forking a Release even before
intake can create one.

- [x] **1.1 — [SCHEMA] [MIGRATION] The pre-flight that refuses.**
  `internal/registry/adapters/store/migrations/000003_registry_uniqueness.up.sql`, one explicit
  transaction (`BEGIN; … COMMIT;`) whose first statement after `BEGIN` is
  `LOCK TABLE products, projects, releases IN SHARE ROW EXCLUSIVE MODE` (writes quiesced from the
  pre-flight through the last index, reads allowed — EDR B4, revision 2), then a `DO` block that
  `RAISE EXCEPTION`s when any duplicate exists, **naming the offending
  groups** (value + row count + the ids, capped) for products (`lower(name)`), projects
  (`product_id, lower(name)`) and releases (`project_id, version`). It **never merges or
  reassigns** (B4).
  *Package:* `internal/registry/adapters/store`.
  *Tests* (`store_integration_test.go`, `-tags=integration`):
  `TestUniquenessMigrationWriterWaitsThenSucceeds` — deterministic, wait-then-resume:
  (1) connection A executes the file's statements up to and including the pre-flight inside its open
  transaction, holding the lock; (2) connection B starts a **non-duplicate** `INSERT INTO products`
  in a goroutine, with **no** short `lock_timeout`; (3) assert B has **not** completed while A holds
  the lock (B's result channel stays empty for a bounded wait, e.g. 300 ms, and `pg_locks` shows B
  waiting); (4) A runs the index statements and commits; (5) assert B's **original** insert completes
  successfully within a bounded deadline (e.g. 5 s) and the row is present. Every wait is bounded by
  a test context so a regression fails instead of hanging the suite;
  `TestUniquenessMigrationRefusesCaseInsensitiveDuplicateProducts` — seed `"OAMP"` + `"oamp"`,
  assert migrate-up fails and the message names **both** ids;
  `TestUniquenessMigrationRefusalNamesEveryLevel` — one duplicate per level, all three named.

- [x] **1.2 — [SCHEMA] [MIGRATION] The three named unique indexes.**
  Same migration, after 1.1: `registry_products_name_key ON products (lower(name))`,
  `registry_projects_product_name_key ON projects (product_id, lower(name))`,
  `registry_releases_project_version_key ON releases (project_id, version)` — **exact** for version
  (B4: a build string's case is not Themis's to fold). Down migration drops **the three indexes
  only** and touches no data.
  *Package:* `internal/registry/adapters/store`.
  *Tests:* `TestRegistryUniquenessConstraintsEnforced` — a duplicate insert at each level fails with
  `23505` naming the expected index; `TestRegistryUniquenessMigrationReversible` — up → down → up on
  a seeded DB, row counts and ids unchanged, and after `down` a duplicate insert **succeeds** (proving
  the down actually dropped them).

- [ ] **1.3 — Product find-or-create.** `UpsertProduct` in `internal/registry/adapters/store/store.go`:
  `INSERT … ON CONFLICT (lower(name)) DO NOTHING RETURNING id`, and on `pgx.ErrNoRows` read the
  winner back by `lower(name)`. Returns `(id, created bool, err)`. Note the expression must be
  restated in `ON CONFLICT` (design §5, trap 1) and the generated id is discarded on a conflict
  (trap 2).
  *Package:* `internal/registry/adapters/store`.
  *Tests:* `TestUpsertProductReturnsExistingIDAndFirstCasing` — insert `"OAMP"`, upsert `"oamp"`,
  assert same id, `created=false`, stored name still `"OAMP"`.

- [ ] **1.4 — Project find-or-create.** `UpsertProject`, `ON CONFLICT (product_id, lower(name))`.
  Same shape as 1.3; the same project name under a **different** product is a different row.
  *Package:* `internal/registry/adapters/store`.
  *Tests:* `TestUpsertProjectIsScopedToItsProduct` (same name, two products → two rows, both
  `created=true`) and `TestUpsertProjectReturnsExistingID`.

- [ ] **1.5 — Release find-or-create.** `UpsertRelease`, `ON CONFLICT (project_id, version)`.
  Version matching is **exact**: `"R1917.25"` is not `"R1917.256"` and `"r1917.256"` is not
  `"R1917.256"`.
  *Package:* `internal/registry/adapters/store`.
  *Tests:* `TestUpsertReleaseIsExactOnVersion` (case- and prefix-distinct versions are distinct
  rows) and `TestUpsertReleaseReturnsExistingID`.

- [ ] **1.6 — Concurrency: one row, one id, no error.** The property the constraints exist for.
  *Package:* `internal/registry/adapters/store`.
  *Tests* (`-tags=integration`): `TestUpsertConcurrentCallersConvergeOnOneRow` — N goroutines upsert
  the same product / project / version simultaneously; assert exactly one row per level, every
  caller returns the same id, exactly one reports `created=true`, and **no caller errors**.

- [ ] **1.7 — App: the three creates become find-or-create.**
  `RegisterProduct` / `RegisterProject` / `RegisterRelease` in `internal/registry/app/service.go`
  return `(id, created bool, err)` and delegate to the upserts. The `ProductExists` /
  `ProjectExists` pre-checks stay — they produce the named `ErrUnknownProduct` /
  `ErrUnknownProject`, which the FK alone cannot — but they are no longer load-bearing for
  uniqueness.
  *Package:* `internal/registry/app` (100% tier).
  *Tests* (`service_test.go`): `TestRegisterProductFindOrCreateReportsCreated`,
  `TestRegisterProjectUnknownProductStillNamed`, `TestRegisterReleaseFindOrCreateReportsCreated`.

- [ ] **1.8 — [API] `200` beside `201` on the three create routes.**
  `api/registry.openapi.yaml`: document the `200` response and add `created` to the three create
  responses; regenerate with `make generate-api-registry`. Handler maps `created → 201`,
  `!created → 200`.
  *Package:* `internal/registry/adapters/http`.
  *Tests* (`handler_test.go`): `TestCreateProductIs201NewAnd200Existing`,
  `TestCreateProjectIs201NewAnd200Existing`, `TestCreateReleaseIs201NewAnd200Existing` — each
  asserting the body's `created` flag agrees with the status; and, `-tags=integration`,
  `TestConcurrentCreateStatusAgreesWithCreatedFlag` — N parallel `POST /releases` for one version:
  exactly one `201` with `created=true`, the rest `200` with `created=false`, all the same id.
  **Consumer compatibility (verified 2026-10-12, recorded here, re-checked by this step):** the
  only callers of the three create routes are `scripts/gf-upload-sbom.sh` (reads `.id`, no status
  check — tolerates `200`), `scripts/run-alpine-e2e-local.sh` (`curl -f`, reads `.id` — `200` is
  success), `tests/pipeline/pipeline_test.go` (expects `201` for a product created once on a fresh
  database — still `201`) and the Registry's own tests. Governance, Communication, Intelligence and
  the dashboard only READ Registry. The step re-runs that search
  (`rg -n 'api/v1/(products|projects|releases)' scripts tests cmd internal`) and updates this list if
  it has grown; the `200` response is documented in `api/registry.openapi.yaml` and API.md.

- [ ] **1.9 — Name lookups abstain, and say *ambiguous*.** Move the exact-name resolution into
  `internal/registry/adapters/store` as `ProductIDByName` / `ProjectIDByName` /
  `ReleaseIDByVersion`: `0` matches → empty id, `nil` error; `>1` → `app.ErrAmbiguousName` (new
  sentinel in `internal/registry/app`). `ReleaseIDByVersion` **stops returning the first match**
  (today `cmd/evidence/main.go:413` scans and takes the first exact hit) and abstains instead.
  *Packages:* `internal/registry/{app,adapters/store}`.
  *Tests:* `TestProductIDByNameAbstainsOnMoreThanOneMatch`,
  `TestReleaseIDByVersionAbstainsInsteadOfPickingTheFirst` — both seeded **before** the 1.2 indexes
  are applied (or on a table without them), because that is the only estate shape where `>1` is
  reachable; and `TestNameLookupMissIsNotAnError` (0 matches stays empty-id + nil).

- [ ] **1.10 — The seam translates, and carries primitives only.**
  `internal/evidence/adapters/subjectref`: add `ErrAmbiguousName` (owned by **this** context) and
  document it on the `Registry` interface. `cmd/evidence/main.go`'s `registryReader` becomes thin
  delegation to 1.9 plus the sentinel translation — no registry error value crosses the seam.
  Resolver maps it to `domain.Reject(ReasonAmbiguousName, …)` with wording that says **ambiguous**,
  never not-registered.
  *Packages:* `internal/evidence/adapters/subjectref`, `cmd/evidence`.
  *Tests* (`resolver_test.go`): `TestResolveAmbiguousNameIsNotReportedAsNotRegistered` — asserts the
  reason is `ambiguous_name` **and** that the detail string does not contain "not registered".
  (Depends only on 0.1 for the enum value.)

- [ ] **1.11 — Group gate.** `make vet-tags`, `make check` green; coverage tiers for
  `registry/app` (100%) and `registry/adapters/store` (80%) still pass — both are already registered
  in `scripts/check-coverage.sh`.

---

## Group 2 — Intake: `create_release`, non-leaking authorization, `build_id` (B1, B2, B3, B5, B6)

- [ ] **2.1 — [API] The two query parameters and the receipt field.**
  `api/evidence.openapi.yaml`: `create_release` (boolean, query), `build_id` (string, query,
  `maxLength: 256`, described as **Unicode code points**), `IntakeReceipt.build_id`. The four reasons
  already landed in 0.1. Additive only; the `POST /evidence` **schema** is unmodified (its new
  ownership check, 2.6b, changes no request or response shape). Regenerate with
  `make generate-api-evidence`.
  *Package:* `api`, `internal/evidence/adapters/http/gen`.
  *Tests:* `internal/evidence/adapters/http/contract_test.go` — the spec's `RejectReason` enum and
  the Go enum are the same set (extend the existing contract assertion; it must fail if either side
  grows alone).

- [ ] **2.2 — Domain: `Provenance.BuildID`.**
  (The four reasons landed in 0.1.) `internal/evidence/domain/evidence.go` gains `Provenance.BuildID` (data, never a modeled
  entity — the standing of the image digest, EDR-KERNEL-01 D2).
  *Package:* `internal/evidence/domain` (100% tier).
  *Tests:* `TestProvenanceCarriesBuildIDAsData` — a `Provenance` with only a `BuildID` is valid and
  `NewEvidence` keeps it verbatim.

- [ ] **2.3 — [SCHEMA] [MIGRATION] `provenance_build_id` and the receipt's `build_id`.**
  `internal/evidence/adapters/store/migrations/000004_evidence_build_id.{up,down}.sql`:
  `ALTER TABLE evidence ADD COLUMN provenance_build_id TEXT NOT NULL DEFAULT ''` and
  `ALTER TABLE intake_receipts ADD COLUMN build_id TEXT NOT NULL DEFAULT ''`. Down drops both.
  Codec read/write updated.
  *Package:* `internal/evidence/adapters/store`.
  *Tests:* `store_codec_test.go` — `TestEvidenceCodecRoundTripsBuildID`;
  `store_integration_test.go` — `TestBuildIDPersistsAndReadsBack` and
  `TestBuildIDMigrationReversible` (up → down → up, existing rows intact).

- [ ] **2.4 — Parameter validation: exclusivity, completeness, the bound.**
  `internal/evidence/app/intake.go` (step 1 of EDR B7 / design §3): `create_release=true` **with**
  `release_id` → `create_release_conflict` (400); `create_release=true` without all three of
  `{product, project, version}` → `incomplete_release_triple` (400); `build_id` over **256 Unicode
  code points**, or not valid UTF-8, → `build_id_invalid` (400), **refused, never truncated** (B5);
  counted with `utf8.RuneCountInString`, never `len`. An incomplete triple **without**
  `create_release` keeps today's `404 unknown_release` — no existing response changes.
  *Package:* `internal/evidence/app` (100% tier).
  *Tests* (`intake_test.go`): `TestCreateReleaseWithReleaseIDIsRefused`,
  `TestCreateReleaseNeedsTheWholeTriple`, `TestIncompleteTripleWithoutCreateReleaseIsUnchanged`,
  `TestBuildIDOverTheBoundIsRefusedNotTruncated`,
  `TestBuildIDBoundCountsCodePointsNotBytes` — 256 × `é` (512 bytes) **accepted**, 257 × `é`
  refused, 256 ASCII accepted, 257 ASCII refused; `TestBuildIDInvalidUTF8IsRefused`;
  `TestParameterValidationPrecedesTheSizeBound` — an oversized body with a 257-code-point `build_id`
  reports `build_id_invalid`, and an oversized body with **no** new parameter still reports
  `payload_too_large` (no existing answer moves).

- [ ] **2.5 — The `ReleaseProvisioner` port and the deferred create.**
  New port in `internal/evidence/app/ports.go` — `FindOrCreateRelease(ctx, projectID, version)
  (id string, created bool, err error)`, one method, no product or project verb (design §2). Wire
  it as step 9 of design §3: **after** every border check, immediately before filing. The resolver
  returns the resolved-or-creatable project id so the create needs no second lookup.
  *Packages:* `internal/evidence/app`, `internal/evidence/adapters/subjectref`, `cmd/evidence`.
  *Tests* (`app/intake_test.go`, fakes): `TestNothingIsCreatedWhenTheDocumentIsRefused` — a
  `schema_invalid` body with `create_release=true` leaves the fake provisioner **uncalled**;
  `TestVersionIsCreatedOnlyOnceAcrossTwoRequests` — the second request finds it (`created=false`);
  `TestFirstFailureStillWins` — an invalid-and-early report reports `schema_invalid`, not a
  release-creation reason (D5 precedence, unchanged).

- [ ] **2.6 — The authorization order, and the non-leak property.**
  `internal/evidence/adapters/http/intake.go` + `app`: authenticate → resolve the product by name →
  **`auth.Principal.AuthorizeProduct(productID)`** → resolve the project → (2.5's create). The three
  product-lookup outcomes a `product:<P>` key must not distinguish — resolves elsewhere, resolves
  nowhere, ambiguous — return **byte-identical** responses.
  *Packages:* `internal/evidence/adapters/http`, `internal/platform/auth` (read-only use).
  *Tests* (`intake_test.go`): `TestProductScopedKeyCannotDistinguishOtherExistingMissingOrAmbiguous`
  — asserts the three responses are **equal as bytes** (status, `reason`, `detail`, headers), not
  merely all 403; `TestAdminIsTold404ForAMissingProductOrProject` (naming which part);
  `TestAuthorizationPrecedesTheProjectLookup` — a fake project lookup that records calls is **never
  called** for an unauthorized key; `TestAuthDisabledNodeTreatsTheCallerAsAdmin`;
  `TestReadAndCallbackScopesAreRefusedByTheWriteFloor`.

- [ ] **2.6b — Authorization on the `release_id` path, on both doors (EDR B7).**
  Add the read `ProductOfRelease(releaseID) (productID string, err error)` to `subjectref.Registry`
  (delegating to Registry's store through `cmd/evidence`'s `registryReader`); intake's step 4 on the
  `release_id` path loads the owning product and calls `AuthorizeProduct`. A `product:<P>` key gets
  the **same** `403` for another product's release and for a release that does not exist; `admin`
  keeps `404 unknown_release`. `POST /evidence` gets the same check.
  *Packages:* `internal/evidence/adapters/{subjectref,http}`, `internal/evidence/app`,
  `cmd/evidence`.
  *Tests:* `TestProductKeyCannotFileAgainstAnotherProductsRelease` (intake **and** `POST /evidence`);
  `TestProductKeyCannotDistinguishForeignFromMissingReleaseID` — the two `403`s equal as bytes;
  `TestAdminStillGets404ForAMissingReleaseID`; `TestProductKeyFilesAgainstItsOwnRelease`; and the
  architecture assertion of 2.10 still sees exactly one **write** on the seam.

- [ ] **2.7 — `build_id` captured and echoed.** Plumb `build_id` from the query into
  `Provenance.BuildID` and onto the receipt (both the synchronous response and `GET
  /intake/{intake_id}`, which is why 2.3 adds the receipt column).
  *Packages:* `internal/evidence/adapters/http`, `internal/evidence/app`.
  *Tests* (`intake_test.go`): `TestBuildIDIsEchoedOnTheReceiptAndStoredOnTheEvidence`;
  `TestBuildIDIsOptional` (absent → empty, never an error).

- [ ] **2.8 — `build_id` is inert, and dedup keeps the first one.**
  No code beyond 2.7 — this step is the **assertions** that make B5's inertness checkable.
  *Packages:* `internal/evidence/adapters/http`, `internal/evidence/adapters/store`.
  *Tests:* `TestTwoSubmissionsDifferingOnlyInBuildIDFileOneEvidenceRow` (dedup is untouched by
  `build_id`); `TestDedupKeepsTheFirstBuildIDAndTheRetryReceiptCarriesItsOwn` — asserts the two
  values **differ**, which is the design, not a bug (design §6).

- [ ] **2.9 — The unchanged behaviours, asserted (B6).** Regression guards, no production code.
  *Packages:* `internal/evidence/adapters/http`, `internal/evidence/adapters/store`.
  *Tests:* `TestByteIdenticalContentOnAnotherReleaseIsStill409` (`duplicate_other_release`);
  `TestADifferentSBOMForTheSameReleaseIsFiledAsNewHistory` — both evidence rows retained, which is
  what **EDR-DELIVERY-01 M2-5**'s per-release baseline rests on; `TestSBOMBeforeReportStillEnforced`
  including a brand-new version with `create_release=true` → `no_inventory_for_release` **and the
  provisioner uncalled**, and the `allow_without_sbom` path → created.

- [ ] **2.10 — Architecture: the seam has exactly one write.**
  *Package:* `tests/architecture`.
  *Tests:* `TestEvidenceRegistrySeamExposesOneWrite` — the `subjectref` write port has a single
  method and no product/project verb; `TestEvidenceDoesNotImportRegistry` — no
  `internal/evidence/…` package imports `internal/registry/…` (only `cmd/evidence` may).

- [ ] **2.11 — Group gate.** `make vet-tags`, `make check` green; `clean-arch` green (it scans test
  files, so a cross-ring test in the wrong directory fails it); coverage tiers for
  `evidence/{domain,app}` (100%) and `evidence/adapters/{http,store,subjectref}` (90%) pass.

---

## Group 3 — Scripts and docs

- [ ] **3.1 — `scripts/gf-upload-sbom.sh` can drive the bot road.** Add `-c` (`create_release=true`,
  valid only with the triple) and `-b <build_id>`, both documented in the script's `usage()`. Keep
  every existing flag and behaviour — the script is muscle memory for documented procedures.
  Fenced examples must stay **paste-safe** (every interstitial comment inside a fence starts with
  `#`; no bash `VAR=value cmd` prefix — `env VAR=value cmd`).
  *Verification:* `scripts/release-smoke-test.sh` still passes end to end; a `-c` run against an
  unregistered version registers it once and a re-run reuses it.

- [ ] **3.2 — `INSTALLATION.md`: the bot section.** How a CI pipeline uploads: two requests (B1),
  the triple + `create_release=true`, `build_id`, and the **`product:<id>` key** it should hold —
  with the non-leak behaviour stated plainly, so an operator debugging a `403` knows it means "this
  key is not for this product" and **not** "that product does not exist".

- [ ] **3.3 — `TESTING.md`: the status-code table and the two-request order.** Mirror the EDR
  amendment's table (not a paraphrase of it) and restate that SBOM-before-report holds **across**
  the two requests.

- [ ] **3.4 — `docs/engineering/decisions/EDR-SECURITY-01.md` realization note.** One paragraph: the
  Evidence intake route now authorizes `product:<id>` against the resolved product explicitly,
  closing that part of **D4**'s deferral in the same shape N-M0 closed it for Governance; the rest
  of the Evidence write surface keeps the method-based floor.

- [ ] **3.5 — `docs/engineering/PHASE3-STATUS.md` + `openspec/STATUS.md`:** record the change, its
  milestones and its state, so the next session resumes from the status page as CLAUDE.md says.

- [ ] **3.6 — Group gate.** No code change in this group; `make check` must still be green, and the
  markdown must be clean under the repo's markdownlint config.

---

## Group 4 — Verification

- [ ] **4.1 — Re-run the VM duplicate census BEFORE 1.2 ships.** Read-only SQL on the running
  estate, one query per level: `products` grouped by `lower(name)`, `projects` by
  `(product_id, lower(name))`, `releases` by `(project_id, version)`, each `HAVING count(*) > 1`.
  The 2026-10-12 census found none, **including case-insensitive collisions**; this re-run is what
  makes the refuse-don't-repair migration a cheap guarantee instead of a blocked upgrade.
  *Record the output* as an addendum in `docs/engineering/vm-test-2026-10-12.md` (or the current
  round's note). If it finds any, **stop**: resolving them is an estate decision for the owner, not
  a migration.

- [ ] **4.2 — The bot test, end to end, two requests.** `-tags=e2e`, `tests/e2e/`:
  `TestBotIntakeCreateReleaseThenScanReport` — with a `product:<id>` key, (1) `POST /intake` with
  the triple + `create_release=true` + `build_id` and an SBOM → `201`, receipt echoes `build_id`,
  the version exists in Registry; (2) the same triple **without** `create_release` and a scan report
  → `201`, filed against **the same** release id; (3) replay request (1) byte-identical with a
  **different** `build_id` → `200 created=false`, the evidence row keeps the **first** `build_id`,
  the receipt carries the second. Assert Registry holds **one** release.

- [ ] **4.3 — The non-leak matrix on a real auth-enabled node.** Same e2e harness, auth on:
  a `product:<P>` key against another product's name, a nonexistent name, and (pre-index seed) an
  ambiguous name → three byte-identical `403`s; an `admin` key → `404 unknown_release` naming the
  part that missed.
  Same matrix on the **`release_id` path** and on **`POST /evidence`**: a `product:<P>` key naming
  another product's release id and a nonexistent release id → two byte-identical `403`s; its own
  release id → filed; `admin` with a nonexistent id → `404`.

- [ ] **4.4 — Concurrency on a real node.** Two simultaneous `create_release=true` requests for the
  same unregistered version → **one** Release, two successful responses. This is the defect the
  constraints exist for and the one a single-threaded test cannot see.

- [ ] **4.5 — `scripts/vm-verify.sh` stays truthful.** Confirm the read-only report still reads the
  EXPECTED migration version **from the migrations directory** (never a literal) now that Registry
  has a third migration and Evidence a fourth — the defect that left the systemd installer loading
  only the first registry migration.

- [ ] **4.6 — Final gate.** `make vet-tags` · `make check` · `make check-ci` · `make e2e-evidence`
  green; `openspec validate phase3-bot-intake` (expect **no deltas** — phase3 convention); archive
  with `openspec archive phase3-bot-intake --skip-specs -y`.

---

## Out of scope (do not drift into these)

Each is recorded in `proposal.md`'s Non-goals with its reason. A task that starts touching one of
them has left this change:

- **current-SBOM ("effective inventory") selection** and **finding reconciliation** — behind a
  design gate, filed as **"Current SBOM and finding cleanup"** in `docs/BACKLOG.md`;
- **`build_id` correlation** — it is a label; nothing reads it;
- **changing EDR-DELIVERY-01 M2-5** or the `ci_rebuild` callback;
- **longer receipt retention**;
- **product-scope isolation on the rest of the Evidence write surface**;
- **merging or repairing duplicate Registry rows.**
