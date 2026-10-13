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

- [x] **1.3 — Product find-or-create.** `UpsertProduct` in `internal/registry/adapters/store/store.go`:
  `INSERT … ON CONFLICT (lower(name)) DO NOTHING RETURNING id`, and on `pgx.ErrNoRows` read the
  winner back by `lower(name)`. Returns `(id, created bool, err)`. Note the expression must be
  restated in `ON CONFLICT` (design §5, trap 1) and the generated id is discarded on a conflict
  (trap 2).
  *Package:* `internal/registry/adapters/store`.
  *Tests:* `TestUpsertProductReturnsExistingIDAndFirstCasing` — insert `"OAMP"`, upsert `"oamp"`,
  assert same id, `created=false`, stored name still `"OAMP"`.

- [x] **1.4 — Project find-or-create.** `UpsertProject`, `ON CONFLICT (product_id, lower(name))`.
  Same shape as 1.3; the same project name under a **different** product is a different row.
  *Package:* `internal/registry/adapters/store`.
  *Tests:* `TestUpsertProjectIsScopedToItsProduct` (same name, two products → two rows, both
  `created=true`) and `TestUpsertProjectReturnsExistingID`.

- [x] **1.5 — Release find-or-create.** `UpsertRelease`, `ON CONFLICT (project_id, version)`.
  Version matching is **exact**: `"R1917.25"` is not `"R1917.256"` and `"r1917.256"` is not
  `"R1917.256"`.
  *Package:* `internal/registry/adapters/store`.
  *Tests:* `TestUpsertReleaseIsExactOnVersion` (case- and prefix-distinct versions are distinct
  rows) and `TestUpsertReleaseReturnsExistingID`.

- [x] **1.6 — Concurrency: one row, one id, no error.** The property the constraints exist for.
  *Package:* `internal/registry/adapters/store`.
  *Tests* (`-tags=integration`): `TestUpsertConcurrentCallersConvergeOnOneRow` — N goroutines upsert
  the same product / project / version simultaneously; assert exactly one row per level, every
  caller returns the same id, exactly one reports `created=true`, and **no caller errors**.

- [x] **1.7 — App: the three creates become find-or-create.**
  `RegisterProduct` / `RegisterProject` / `RegisterRelease` in `internal/registry/app/service.go`
  return `(id, created bool, err)` and delegate to the upserts. The `ProductExists` /
  `ProjectExists` pre-checks stay — they produce the named `ErrUnknownProduct` /
  `ErrUnknownProject`, which the FK alone cannot — but they are no longer load-bearing for
  uniqueness.
  *Package:* `internal/registry/app` (100% tier).
  *Tests* (`service_test.go`): `TestRegisterProductFindOrCreateReportsCreated`,
  `TestRegisterProjectUnknownProductStillNamed`, `TestRegisterReleaseFindOrCreateReportsCreated`.

- [x] **1.8 — [API] `200` beside `201` on the three create routes.**
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
  **Re-checked on implementation (2026-10-12):** the list has not grown, and one entry is
  narrower than recorded — `scripts/run-alpine-e2e-local.sh` posts to the **frozen v0.3.x
  monolith** on `:8080` (`POST /products/{id}/projects`, a route the greenfield Registry does not
  serve), so it is unaffected by this change rather than merely tolerant of it. `gf-upload-sbom.sh`
  uses `curl --fail-with-body`, so `200` is success there. The list now lives beside the tests, on
  `assertFindOrCreate` in `internal/registry/adapters/http/handler_test.go`, where the next person
  to change the status mapping will read it.
  **Two schema-provisioning paths froze at a file literal and had to be fixed here**, because
  1.7 is the first step whose create path actually executes `INSERT … ON CONFLICT` and therefore
  the first that NEEDS 1.2's indexes at runtime: `tests/pipeline/pipeline_test.go` hand-loaded
  `000001_registry.up.sql` (now runs the whole migrations directory through Registry's own
  `registry_schema_migrations`, as `cmd/registry` does — it had also been missing `000002`), and
  INSTALLATION.md's by-hand alternative listed only `000001`/`000002` (now all three, with the
  note that `000003` is not idempotent). Both would otherwise answer `400`
  `no unique or exclusion constraint matching the ON CONFLICT specification` on every create.

- [x] **1.9 — Name lookups abstain, and say *ambiguous*.** Move the exact-name resolution into
  `internal/registry/adapters/store` as `ProductIDByName` / `ProjectIDByName` /
  `ReleaseIDByVersion`: `0` matches → empty id, `nil` error; `>1` → `app.ErrAmbiguousName` (new
  sentinel in `internal/registry/app`). `ReleaseIDByVersion` **stops returning the first match**
  (today `cmd/evidence/main.go:413` scans and takes the first exact hit) and abstains instead.
  *Packages:* `internal/registry/{app,adapters/store}`.
  *Tests:* `TestProductIDByNameAbstainsOnMoreThanOneMatch`,
  `TestReleaseIDByVersionAbstainsInsteadOfPickingTheFirst` — both seeded **before** the 1.2 indexes
  are applied (or on a table without them), because that is the only estate shape where `>1` is
  reachable; and `TestNameLookupMissIsNotAnError` (0 matches stays empty-id + nil).

- [x] **1.10 — The seam translates, and carries primitives only.**
  `internal/evidence/adapters/subjectref`: add `ErrAmbiguousName` (owned by **this** context) and
  document it on the `Registry` interface. `cmd/evidence/main.go`'s `registryReader` becomes thin
  delegation to 1.9 plus the sentinel translation — no registry error value crosses the seam.
  Resolver maps it to `domain.Reject(ReasonAmbiguousName, …)` with wording that says **ambiguous**,
  never not-registered.
  *Packages:* `internal/evidence/adapters/subjectref`, `cmd/evidence`.
  *Tests* (`resolver_test.go`): `TestResolveAmbiguousNameIsNotReportedAsNotRegistered` — asserts the
  reason is `ambiguous_name` **and** that the detail string does not contain "not registered".
  (Depends only on 0.1 for the enum value.)

- [x] **1.11 — Group gate.** `make vet-tags`, `make check` green; coverage tiers for
  `registry/app` (100%) and `registry/adapters/store` (80%) still pass — both are already registered
  in `scripts/check-coverage.sh`.

---

## Group 2 — Intake: `create_release`, non-leaking authorization, `build_id` (B1, B2, B3, B5, B6)

- [x] **2.1 — [API] The two query parameters and the receipt field.**
  `api/evidence.openapi.yaml`: `create_release` (boolean, query), `build_id` (string, query,
  `maxLength: 256`, described as **Unicode code points**), `IntakeReceipt.build_id`. The four reasons
  already landed in 0.1. Additive only; the `POST /evidence` **schema** is unmodified (its new
  ownership check, 2.6b, changes no request or response shape). Regenerate with
  `make generate-api-evidence`.
  *Package:* `api`, `internal/evidence/adapters/http/gen`.
  *Tests:* `internal/evidence/adapters/http/contract_test.go` — the spec's `RejectReason` enum and
  the Go enum are the same set (extend the existing contract assertion; it must fail if either side
  grows alone).

- [x] **2.2 — Domain: `Provenance.BuildID`.**
  (The four reasons landed in 0.1.) `internal/evidence/domain/evidence.go` gains `Provenance.BuildID` (data, never a modeled
  entity — the standing of the image digest, EDR-KERNEL-01 D2).
  *Package:* `internal/evidence/domain` (100% tier).
  *Tests:* `TestProvenanceCarriesBuildIDAsData` — a `Provenance` with only a `BuildID` is valid and
  `NewEvidence` keeps it verbatim.

- [x] **2.3 — [SCHEMA] [MIGRATION] `provenance_build_id` and the receipt's `build_id`.**
  `internal/evidence/adapters/store/migrations/000004_evidence_build_id.{up,down}.sql`:
  `ALTER TABLE evidence ADD COLUMN provenance_build_id TEXT NOT NULL DEFAULT ''` and
  `ALTER TABLE intake_receipts ADD COLUMN build_id TEXT NOT NULL DEFAULT ''`. Down drops both.
  Codec read/write updated.
  *Package:* `internal/evidence/adapters/store`.
  *Tests:* `store_codec_test.go` — `TestEvidenceCodecRoundTripsBuildID`;
  `store_integration_test.go` — `TestBuildIDPersistsAndReadsBack` and
  `TestBuildIDMigrationReversible` (up → down → up, existing rows intact).

- [x] **2.4 — Parameter validation: exclusivity, completeness, the bound.**
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
  **On implementation (2026-10-12):** the check is `IntakeCommand.ParameterRefusal()` in
  `internal/evidence/app/intake.go`, and it is applied in **two** places — step 0 of `Intake`, and
  the HTTP edge before `io.ReadAll`. One implementation, two call sites, for the same reason the
  size bound is checked twice: only the edge can refuse before the body is buffered, and a
  parameter fault discovered after a 60 MB read is reported on the wrong thing. The app tests carry
  the names above; the edge's enforcement is pinned separately in
  `internal/evidence/adapters/http/intake_test.go` (`TestIntakeParameters_*`), because
  `TestParameterValidationPrecedesTheSizeBound` in the app ring cannot see the `MaxBytesReader`.
  `IntakeCommand` gained `CreateRelease` and `BuildID` here (validation needs the values); plumbing
  `BuildID` onto the provenance and the receipt stays 2.7's.

- [x] **2.5 — The `ReleaseProvisioner` port and the deferred create.**
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
  **On implementation (2026-10-12).** The step number is **B7's step 8** (the authoritative order;
  "step 9 of design §3" above predates that renumbering), and five decisions a reviewer should see:
  (1) **How "to be created" travels.** `ReleaseResolver.Resolve` now answers an
  `app.Resolution{ReleaseID | ProjectID+Version}`, and `ToCreate()` is **derived** from an empty
  release id rather than carried as a second field — a resolution that both names a release and
  asks for one cannot be constructed. Resolution stays read-only and consults `create_release` in
  exactly one place: an absent VERSION under a resolved, authorized Product and Project. Every
  other answer is byte-identical, including the two non-leak properties of 2.6/2.6b.
  (2) **Where the create runs.** `app.Intake` step 7 (B7's step 8), between D6 and filing.
  `assertRefused` in `app/intake_test.go` now asserts the provisioner is **uncalled** on EVERY
  refusal, not only in the three named tests, because the create sits one line above the filing
  step and a reordering would otherwise pass. The `created` flag is discarded deliberately: a
  receipt's `created` is about the EVIDENCE (D9), and there is nothing on a receipt that a created
  ROW answers — `TestVersionIsCreatedOnlyOnceAcrossTwoRequests` therefore asserts it through the
  fake, which records what it answered.
  (3) **D6 needs no read for a new version.** A version still to be created has no inventory and no
  id to read one by, so `HasInventory` is **not** called; the refusal names the VERSION instead of
  an empty release id, which is the shape that sends an operator hunting.
  (4) **What the seam delegates to, and why only ONE name is exported.**
  `subjectref.Provisioner.FindOrCreateRelease` is the package's **only exported write**; the
  registry's own verb lives on an **unexported** `releaseWriter` interface inside the adapter and
  delegates to the registry store's `UpsertRelease` (B4's idempotent upsert, where the constraint,
  the id and the `created` answer live). The adapter translates the verb so the registry's
  vocabulary stops there, exactly as the read half translates the ambiguity sentinel — and keeping
  the writer unexported is what makes "exactly one write" true of the **public surface** rather
  than of a count that permits two names. `cmd/evidence` passes its seam value and never names the
  type. The registry **app** service's `RegisterRelease` was the alternative; the store is what B2
  names ("B4's idempotent upsert"), and it keeps the version unnormalized — `domain.NewRelease`
  trims, and B2 says Themis never corrects a version it was given.
  (5) **A node with no write seam.** The stub path wires none (it knows no names, so no triple
  resolves far enough), and `NewIntakeService` replaces a nil provisioner with one that REFUSES:
  a missing seam is a misconfiguration, and the honest answer to one is a sentence naming it
  rather than a panic inside the only step that writes.
  **2.10's write assertion landed here** (`tests/architecture/evidence_subjectref_write_test.go`,
  `TestEvidenceRegistrySeamExposesOneWrite`), because 2.6b left it with nothing to contradict and
  this is the step that gives it something: it enumerates the seam's **exported** methods against a
  named read allow-list, requires the write set to be **exactly one** method named
  `FindOrCreateRelease`, pins its parameter/result shape and refuses a name containing `Product` or
  `Project`. Both failure modes were exercised against the real tree before the gate was trusted —
  a re-exported `UpsertRelease` and a second exported type carrying the permitted verb each fail
  it. 2.10 still owns `TestEvidenceDoesNotImportRegistry`.

- [x] **2.6 — The authorization order, and the non-leak property.**
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
  **On implementation (2026-10-12), three decisions a reviewer should see:**
  (1) **Where the check runs.** The edge reads the principal (only adapters may) and carries the
  decision as `app.ProductAuthorizer` on the command — `nil` meaning "no product confinement
  applies", which is `admin` and an auth-disabled node. The check itself happens inside resolution
  (`subjectref.Resolver`), because B7 puts it at step 4: **after** the body is identified (so an
  unidentifiable body still answers `415`, B7's second stated consequence) and **before** the
  project lookup. Carrying it on the command rather than on the request context is also what makes
  the **overflow worker** authorize: its context is detached from the request, so a confinement
  living on the context would widen to admin exactly when nobody is watching.
  (2) **The `403` names no receipt.** A fresh `intake_id` per request cannot be byte-identical, so
  the response that has to be indistinguishable omits it (it is optional in the spec). The attempt
  is still recorded — D9 is unchanged, and the log carries the key id — and the shape matches the
  middleware's own `403` (row 2), which is the same class of answer.
  (3) **`unauthorized` maps to `403`, not `401`.** Nothing produced the reason before this change
  (a missing key is the middleware's own `401`, which carries no reason), so no existing response
  moves; rows 2/8-10/17-18 all read `403 unauthorized`.
  **One gap left open deliberately, for Group 3 (3.3) or a follow-up:** `api/evidence.openapi.yaml`
  lists `401` but no **`403`** response on `POST /intake`, and neither on `POST /evidence`. Both
  doors can now answer `403` (the body shape is the already-declared `IntakeProblem` / `Problem`, so
  nothing about the schemas changes). Adding the two response entries is additive and needs
  `make generate-api-evidence`; it was left out of this step because the step was scoped to carry no
  spec change.

- [x] **2.6b — Authorization on the `release_id` path, on both doors (EDR B7).**
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
  **On implementation (2026-10-12):** the seam gained a READ only — 2.5's write is not landed yet,
  so the seam currently exposes **zero** writes and 2.10's assertion has nothing to contradict.
  `POST /evidence` is authorized at its own edge (`Handler.authorizeRelease`, Governance's
  `authorizeGovernanceWrite` shape): no principal or `admin` passes with **no Registry read at
  all**, so that door's pre-existing answers — including the `422 unknown subject release` an
  unknown release has always returned there, which is NOT intake's `404` — are untouched. It
  "gains only the ownership check", as B7 says. The check is **fail-closed**: an unreadable seam,
  an unwired seam (`subjectref.Stub`, which knows no products) and an unknown release are all the
  same `403` for a confined key.

- [x] **2.7 — `build_id` captured and echoed.** Plumb `build_id` from the query into
  `Provenance.BuildID` and onto the receipt (both the synchronous response and `GET
  /intake/{intake_id}`, which is why 2.3 adds the receipt column).
  *Packages:* `internal/evidence/adapters/http`, `internal/evidence/app`.
  *Tests* (`intake_test.go`): `TestBuildIDIsEchoedOnTheReceiptAndStoredOnTheEvidence`;
  `TestBuildIDIsOptional` (absent → empty, never an error).
  **On implementation (2026-10-12).** 2.1-2.6b had carried the value as far as
  `IntakeCommand.BuildID` (2.4 needed it to validate) and had rendered `IntakeReceipt.build_id`
  from the receipt row; the two ENDS were missing, and each was one line:
  `app.Intake` built its `domain.Provenance` from the source and the image digest only, and the
  edge never copied `cmd.BuildID` onto the receipt row — so the column existed, the renderer read
  it, and nothing ever wrote it. Both halves were confirmed RED before the fix (the echo test
  reported `""` on the POST body, on the `GET` and on the filed provenance).
  The edge copies it **after** `ParameterRefusal`, not with the rest of the command:
  `intake_receipts.build_id` is `TEXT`, Postgres rejects malformed UTF-8 outright, and recording
  the value first would have turned 2.4's named `400` into a failed write.
  `TestBuildIDIsEchoedOnTheReceiptAndStoredOnTheEvidence` lives in
  `intake_integration_test.go` rather than `intake_test.go`: "stored on the evidence" is a claim
  about a real `provenance_build_id` column, and the unit file's fake use case cannot make it.
  `TestBuildIDIsOptional` stays in `intake_test.go` (no database needed), and asserts the value is
  empty on BOTH receipt surfaces rather than insisting on omitted-vs-`""` — the other optional
  strings on a receipt render as `""`, and pinning the encoding instead of the contract would make
  this a test about `omitempty`.

- [x] **2.8 — `build_id` is inert, and dedup keeps the first one.**
  No code beyond 2.7 — this step is the **assertions** that make B5's inertness checkable.
  *Packages:* `internal/evidence/adapters/http`, `internal/evidence/adapters/store`.
  *Tests:* `TestTwoSubmissionsDifferingOnlyInBuildIDFileOneEvidenceRow` (dedup is untouched by
  `build_id`); `TestDedupKeepsTheFirstBuildIDAndTheRetryReceiptCarriesItsOwn` — asserts the two
  values **differ**, which is the design, not a bug (design §6).
  **On implementation (2026-10-12):** both named tests landed in
  `internal/evidence/adapters/http/intake_integration_test.go`, over the real wiring and a real
  database, because that is the only place the asymmetry is PRODUCED rather than hand-built: the
  store-level alternative would construct a filed row and a receipt row with two different values
  and then assert they differ, which proves nothing about dedup. The store package gained the
  MECHANISM instead, as `TestDedupDoesNotRewriteTheFiledBuildID` (a second `Save` of the same
  bytes with a different build id → one row, the first build id, one outbox note) — the layer where
  `ON CONFLICT … DO NOTHING` is what makes "the first one wins" true.

- [x] **2.9 — The unchanged behaviours, asserted (B6).** Regression guards, no production code.
  *Packages:* `internal/evidence/adapters/http`, `internal/evidence/adapters/store`.
  *Tests:* `TestByteIdenticalContentOnAnotherReleaseIsStill409` (`duplicate_other_release`);
  `TestADifferentSBOMForTheSameReleaseIsFiledAsNewHistory` — both evidence rows retained, which is
  what **EDR-DELIVERY-01 M2-5**'s per-release baseline rests on; `TestSBOMBeforeReportStillEnforced`
  including a brand-new version with `create_release=true` → `no_inventory_for_release` **and the
  provisioner uncalled**, and the `allow_without_sbom` path → created.
  **On implementation (2026-10-12).** All three are in `intake_integration_test.go`, through the
  door: a regression guard for "this answer did not move" has to be asserted where the answer is a
  status code and a reason, not where it is an error value. Three things the step needed:
  (1) the fixture's allow-set stub now knows a SECOND release (`rel-intake-2`), because a
  cross-release duplicate needs a second release to be refused against;
  (2) `liveIntakeWith` lets a test supply the registry read seam and the write seam, because the
  allow-set stub answers every name lookup with "nothing" — so no triple resolves far enough for
  `create_release` to reach the create, and the `create_release` half of D6 is untestable without
  a name-aware seam. `TestSBOMBeforeReportStillEnforced` reuses the auth tests' `authRegistry`
  and `countingProvisioner` rather than adding a third fake estate;
  (3) one gap the reuse exposed: a real Registry's just-created version EXISTS afterwards, and
  filing re-validates the subject release through the same seam — so the fake is wrapped
  (`provisionedRegistry`) to answer accordingly. Without it the create succeeded and the filing
  then refused the release Themis had made one line earlier, which is also a useful record of how
  tightly the two halves of the seam are coupled.
  `TestADifferentSBOMForTheSameReleaseIsFiledAsNewHistory` uses the CycloneDX and SPDX fixtures —
  two genuinely different SBOMs, not the same bytes with a changed byte.

- [x] **2.10 — Architecture: the seam has exactly one write.**
  *Package:* `tests/architecture`.
  *Tests:* `TestEvidenceRegistrySeamExposesOneWrite` — the `subjectref` write port has a single
  method and no product/project verb; `TestEvidenceDoesNotImportRegistry` — no
  `internal/evidence/…` package imports `internal/registry/…` (only `cmd/evidence` may).
  **On implementation (2026-10-12):** `TestEvidenceRegistrySeamExposesOneWrite` landed with 2.5
  (see that step's note) and was re-run here, not duplicated — it still reports the seam's write
  surface as exactly `[Provisioner.FindOrCreateRelease]`. This step added
  `TestEvidenceDoesNotImportRegistry` beside it in the same file, which is the half that makes the
  first one worth having: "one write" would otherwise be a statement about one package while any
  adapter imported `registry/app` and called whatever it liked. It loads
  `internal/evidence/...` with `Tests: true` — a test is also code that compiles, and a test
  reaching into the registry to seed an estate is how the import creeps in (the same reason
  go-cleanarch scans test files) — and it carries a **positive control**: `cmd/evidence` must
  still import a registry package, so the rule cannot pass by the seam having quietly disappeared.
  Verified RED against the real tree with a blank import added to `adapters/subjectref`.

- [x] **2.11 — Group gate.** `make vet-tags`, `make check` green; `clean-arch` green (it scans test
  files, so a cross-ring test in the wrong directory fails it); coverage tiers for
  `evidence/{domain,app}` (100%) and `evidence/adapters/{http,store,subjectref}` (90%) pass.
  **Green 2026-10-12:** `make vet-tags`, `make lint`, `make clean-arch`, `make arch-test`,
  `make e2e-pipeline` and `make check-ci` (which includes the coverage tiers above, and pulls in
  the integration tests the three steps before this one landed). **Group 2 — Gate C — is
  complete**; recorded in `docs/engineering/PHASE3-STATUS.md` and `openspec/STATUS.md`.
  **The store's tier moved, 80% → 90%, which this step's text had asked for all along.**
  `evidence/adapters/store` measured 86% and passed only because `scripts/check-coverage.sh`
  registered it in the **aggregate-store** tier (80%) — so the 90% this step names was being
  measured and not gated, and would have drifted back. The gap was the package's "I could not ask
  the question" branches, and they turned out NOT to need the pool-fault injection the 80% tier was
  justified by: a **cancelled context** reaches every read, both receipt sweeps, `Save`'s `Begin`,
  the relay's outbox read, and — via a publisher that cancels after succeeding — the window where a
  note was PUBLISHED and could not be marked sent. That is the real shape of this on a node (a
  client that hung up, a shutdown mid-sweep), it is deterministic, and the assertions are properties
  rather than line coverage: *a read that could not be performed is never reported as an absence*
  (`ErrNotFound` on a row that is there says a filed document is gone; `HasInventory` answering
  `(false, nil)` tells an operator to upload an SBOM they already uploaded), *a fault is not a retry
  arriving* (`ErrIdempotencyKeyTaken` would send the caller to read back a receipt nobody wrote),
  *a sweep that never ran must not report "nothing was stale"*, and *an unmarked outbox note is
  re-delivered, not dropped*. Now **93.6%**, gated at 90%. The residue — 11 statements — is a fault
  arriving AFTER a statement has succeeded inside `Save`'s transaction (dedup-resolve, the insert
  error that is not a fingerprint conflict, the outbox insert, the two commits) plus two row-scan
  branches the schema's `NOT NULL DEFAULT` columns make unconstructible; those still want the
  injectable pgxpool, which stays the tracked follow-up. `registry/adapters/store` and the other
  aggregate stores are untouched at 80%.

---

## Group 3 — Scripts and docs

- [x] **3.1 — `scripts/gf-upload-sbom.sh` can drive the bot road.** Add `-c` (`create_release=true`,
  valid only with the triple) and `-b <build_id>`, both documented in the script's `usage()`. Keep
  every existing flag and behaviour — the script is muscle memory for documented procedures.
  Fenced examples must stay **paste-safe** (every interstitial comment inside a fence starts with
  `#`; no bash `VAR=value cmd` prefix — `env VAR=value cmd`).
  *Verification:* `scripts/release-smoke-test.sh` still passes end to end; a `-c` run against an
  unregistered version registers it once and a re-run reuses it.
  **On implementation (2026-10-13), four decisions a reviewer should see:**
  (1) **`-c` requires the triple EXPLICITLY**, not merely non-empty. `PRODUCT` defaults to the SBOM's
  base name, `PROJECT` to `"default"` and `VERSION` to `"1.0.0"`, so "the triple is present" is
  trivially true on every run and would have made `-c` send a defaulted `default` project at a door
  that answers B3's **non-disclosing** `403`. The flags therefore carry a "was it given" bit, and the
  check runs **before** the defaulting, so a `-c` run can never fall back to a derived name.
  (2) **The triple is percent-encoded with `jq @uri`**, not with curl's `-G`/`--data-urlencode`: `-G`
  moves EVERY `--data*` argument into the query string, including the `--data-binary` carrying the
  document, and curl then refuses outright (the defect already recorded in TESTING.md). `jq` is
  already a hard requirement of the script.
  (3) **The release id is read off the receipt** (`release_id`) on the `-c` road, because this run
  makes no registration call to capture it from — so the script's final `RELEASE_ID=…` + posture line,
  which every runbook depends on, keeps working on both roads.
  (4) **The extension strip stays exactly as it was**, by review decision (2026-10-13). The original
  line is `[[ -n "$PRODUCT" ]] || PRODUCT="$(basename …)"; PRODUCT="${PRODUCT%.*}"`, whose `;` makes
  the strip run on **whatever** `$PRODUCT` holds — so `-p my.app` has always been sent as `my`. A
  first pass narrowed the strip to the derived default; that is a change to existing behaviour, which
  **this task forbids**, so it was reverted. The hazard is documented instead, in `usage()` under `-p`
  and beside the line: a product whose registered name contains a dot cannot be addressed through this
  script, and on the `-c` road the truncated name does not resolve — which for a product-scoped key is
  B3's non-disclosing `403` with nothing in it to point at the cause. **Relaxing this needs the
  owner's say-so and is not taken here.** One new-road-only guard was added: `-c` with a `-p` that
  strips to the empty string (`-p .json`) refuses locally rather than sending `product=`.
  (5) **Stdout shape is preserved** (review): the two lines this step adds for the operator (`bot
  road: …` and `build_id=…`), and the "receipt named no `release_id`" fallback, all go to **stderr**,
  so a caller grepping stdout for `RELEASE_ID=` or the registration line sees the stream it saw
  before. The receipt's release id is read with `jq -er` inside an `if`, so the exit status decides
  and nothing is assigned-then-unset; the two `Content-Type` headers are spelled consistently.
  (6) **`THEMIS_API_KEY` is refused if it contains whitespace** (security review). The array form
  (`CURL+=(-H "X-API-Key: $THEMIS_API_KEY")`) already prevents word-splitting, and a minted key is
  `thm_` + base64url, so the guard cannot fire for a real key; it exists for the way this actually
  goes wrong — a token pasted with a stray newline, which otherwise reaches the operator as an
  unreadable `401` instead of a sentence naming the cause. Stated in `usage()` too. **There is no
  duplicate `Content-Type` on the intake call** (also raised in review): that call uses `CURL`,
  which carries no content type, while `J` — the only arg set that does — is used by `register_id`
  alone; a comment now says so at the call site.
  **Not verified here:** this harness permits no shell interpreter, `make` or `go` invocation, so
  `bash -n`, a scripted local run and `scripts/release-smoke-test.sh` were **not** executed — the
  script was reviewed by reading. The smoke test does not call `gf-upload-sbom.sh` (it drives the API
  directly), and with (4) reverted **no non-`-c` behaviour changes at all**.

- [x] **3.2 — `INSTALLATION.md`: the bot section.** How a CI pipeline uploads: two requests (B1),
  the triple + `create_release=true`, `build_id`, and the **`product:<id>` key** it should hold —
  with the non-leak behaviour stated plainly, so an operator debugging a `403` knows it means "this
  key is not for this product" and **not** "that product does not exist".
  **On implementation:** landed as **§5b** (after 5a, so no existing section number moves). It states
  that a human creates the Product and the Project first, shows the two requests in order, shows the
  same thing through `gf-upload-sbom.sh -c -b`, names the `build_id` bound and its dedup asymmetry,
  and mints the key with `go run ./cmd/authadmin create-key --scopes "product:$PID"` — `go run`, not
  `./bin/authadmin`, because step 2's build line does not include `./cmd/authadmin` (the note says
  both forms are shown, `go run` live and the built `./bin/authadmin` beside it, commented).
  **Every example URL carries an explicit `http://` scheme** (security review): curl guesses a
  scheme for a bare `host:port`, but an example an operator pastes should not depend on the guess,
  so all ten new URLs in TESTING.md and all three in INSTALLATION.md were corrected. The
  scheme-less URLs that remain in both files are **older examples outside this change's sections**;
  normalizing them is a separate, whole-file edit. Ports and env names re-checked against the code
  (2026-10-13): Evidence `:8081` and Registry `:8082` are the `cmd/*` defaults, and
  `THEMIS_AUTH_DATABASE_DSN` / `THEMIS_AUTH_MIGRATE` / `--name` / `--scopes` / `--ttl` are
  `cmd/authadmin`'s actual names.

- [x] **3.3 — `TESTING.md`: the status-code table and the two-request order.** Mirror the EDR
  amendment's table (not a paraphrase of it) and restate that SBOM-before-report holds **across**
  the two requests.
  **On implementation:** a new `### Bot intake …` section before `### Trust model`. The 19 rows and
  the rows-5-and-6 note are **copied**, and the copy is verified **mechanically**: the header line
  plus the following 23 lines were extracted from both files (`grep -A23` on the table header) and
  `diff`ed — identical, character for character, re-run after the review. One correction the copy
  forced: the draft claimed `GET /evidence/{id}` shows the filed `build_id` — it does **not**
  (`EvidenceFacts` carries `provenance_source` and `provenance_image_digest` only), so the asymmetry
  is demonstrated against the `provenance_build_id` column instead of against an API that would have
  answered nothing. Row 10 (ambiguous) is noted as unreproducible on a migrated node and asserted in
  Go, which is where B4 put it. Every example URL in the section carries an explicit `http://`
  scheme (see 3.2's note).

- [x] **3.4 — `docs/engineering/decisions/EDR-SECURITY-01.md` realization note.** One paragraph: the
  Evidence intake route now authorizes `product:<id>` against the resolved product explicitly,
  closing that part of **D4**'s deferral in the same shape N-M0 closed it for Governance; the rest
  of the Evidence write surface keeps the method-based floor.
  **Corrected on implementation:** since **2.6b** this is true of **BOTH** `POST /api/v1/intake`
  **and** the older `POST /api/v1/evidence` — the task's wording named intake only, and B7 revision 1
  is what widened it (the old door was otherwise a way around the new one). The note says both doors,
  names the two roads (name → Product → authorize → Project; `release_id` → project → owning product
  → authorize), records that the check is fail-closed and non-disclosing and that the **one** moved
  response is a `product:<P>` key naming a non-existent `release_id` (`404` → `403`), and keeps the
  method floor for everything else. The pre-existing bullet that said the deferral "stands" for the
  other contexts gained a pointer to it, so the bullet is not read alone and left stale.

- [x] **3.5 — `docs/engineering/PHASE3-STATUS.md` + `openspec/STATUS.md`:** record the change, its
  milestones and its state, so the next session resumes from the status page as CLAUDE.md says.
  **On implementation:** both now read **Groups 0–3 complete, Group 4 (verification on the VM) next**,
  with Group 4's six steps in order and the three things Group 3 left alone on purpose (the
  undeclared `403` in `api/evidence.openapi.yaml`, which needs `make generate-api-evidence` and
  therefore a code change this group does not carry; `EvidenceFacts` not exposing
  `provenance_build_id`; and `gf-upload-sbom.sh`'s unconditional extension strip, documented and
  awaiting the owner's call rather than fixed in passing).

- [x] **3.6 — Group gate.** No code change in this group; `make check` must still be green, and the
  markdown must be clean under the repo's markdownlint config.
  **On implementation:** no Go file is touched (the diff is one shell script and five markdown files),
  so the gate is the one Gate C left green. The harness this group ran in permits no `make`, `go`,
  `bash` or `markdownlint` invocation, so **neither was executed here** — markdown was checked by
  rule instead, and re-checked after the review: every added prose line is within MD013's 120
  (tables and code blocks are exempt / bounded at 200 in `.markdownlint.json`, and the only >120
  additions are table rows and one 124-char URL inside a fence — the >120 prose lines that do exist
  in these files all predate this change), headings and fences are blank-line-separated, every fence
  carries a language, and no line gained trailing whitespace (MD009).
  The repository ships no markdownlint runner (no `Makefile` target, no CI step) — only the two
  config files. **`make check` is the orchestrator's to run, and so are
  `bash -n scripts/gf-upload-sbom.sh` and any configured markdown lint** — both were asked for in
  review and neither can be invoked from here.

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

- [x] **4.2 — The bot test, end to end, two requests.** `-tags=e2e`, `tests/e2e/`:
  `TestBotIntakeCreateReleaseThenScanReport` — with a `product:<id>` key, (1) `POST /intake` with
  the triple + `create_release=true` + `build_id` and an SBOM → `201`, receipt echoes `build_id`,
  the version exists in Registry; (2) the same triple **without** `create_release` and a scan report
  → `201`, filed against **the same** release id; (3) replay request (1) byte-identical with a
  **different** `build_id` → `200 created=false`, the evidence row keeps the **first** `build_id`,
  the receipt carries the second. Assert Registry holds **one** release.
  **On implementation:** `tests/e2e/bot_intake_e2e_test.go`, all three steps as written. The harness
  is new and is the substance of this group: the package's existing suite wires an **allow-set stub**
  registry (`subjectref.NewStub`), on which no triple resolves and `create_release` is unreachable by
  construction — so a bot test on it could only have asserted the refusal. `startBotNode` therefore
  wires the **real** Registry (its HTTP API for Product/Project, `registrystore` behind Evidence's
  read+write seam, mirroring `cmd/evidence`'s `registryReader`) **and the real inbound-edge auth
  middleware with real minted keys**, over a database of its own on the suite's embedded Postgres.
  Verified: step 1 → `201`, `build_id=build-1`, `created=true`, and `GET /projects/{id}/releases`
  (Registry's own API, not an Evidence table) returns exactly `[R2026.001]` with the id the receipt
  named; step 2 → `201` on the **same** release id, `detected_kind/format = vuln-report/curated`, a
  **different** evidence id; step 3 → `200`, an explicit `created=false`, the same evidence id,
  `build_id=build-2` on the receipt while `evidence.provenance_build_id` is still `build-1` (B5's
  asymmetry, read straight from the column because no API exposes it — 3.3's correction), and
  Registry still holds exactly one release after all three requests.
  Two deliberate harness choices: the inline budget is **60s** (a `202` from a slow embedded
  Postgres would turn a real failure into an `accepted` receipt), and the three SBOMs across this
  file are **distinct documents**, because Evidence is content-addressed and the same bytes aimed at
  a second release are a loud `409` by design (D3 note) — a test that files twice needs two
  documents, not two releases for one document.
  **Wiring, as it actually is** (review ask — these were verified against the current code, not
  assumed): `wiring.EvidenceAPI(wiring.Config) (http.Handler, *store.Store, *evhttp.Intake)`, with
  the inline budget set through `Config.Intake` (an `evhttp.IntakeConfig`, whose zero fields take the
  documented defaults), and `wiring.RegistryAPI(*pgxpool.Pool) (http.Handler, *store.Store)`. The
  handler is mounted under `/api/v1`, the `*Intake` is `Close`d on cleanup, and both `*Store` returns
  are unused here (they exist for the relay and dev-purge the binaries run). `go vet -tags=e2e` and
  the suite run are the standing proof.
  **Bookkeeping-table isolation is asserted, not assumed** (review ask): three schemas share this
  database, so `botMigrate` reads back each one's applied version and compares it with the HIGHEST
  `*.up.sql` on disk (`botHighestMigration` — derived, never a literal, the same rule as 4.5). Two
  schemas sharing one bookkeeping table is otherwise a SILENT defect. Demonstrated by breaking it on
  purpose: pointing Registry at the default `schema_migrations` fails at setup with
  `no migration found for version 4` (it had read Evidence's version), and the check restores the
  loud failure wherever golang-migrate itself would not have objected.
  **The golang-migrate driver imports are repeated in this file** (review ask): `migrate.New`
  resolves a source and a database by NAME at run time, from registries the driver packages fill in
  `init()`, so `_ ".../source/file"` and `_ ".../database/postgres"` are what make `file://` + a
  Postgres DSN resolvable at all. They were reachable only through the sibling harness file, which
  made this file's `botMigrate` depend on an import it did not declare — dropping it there would have
  produced `no source: file` at run time with nothing in THIS file to point at. Repeating them is
  free: a package's `init()` runs once per binary however many files import it, so the duplicate
  cannot double-register (both `Register` functions PANIC on a repeated name, which is also the
  instant proof — the suite would abort at start, and does not). Verified by removing them from the
  sibling file: the whole suite still passes, so the registration now comes from here.

- [x] **4.3 — The non-leak matrix on a real auth-enabled node.** Same e2e harness, auth on:
  a `product:<P>` key against another product's name, a nonexistent name, and (pre-index seed) an
  ambiguous name → three byte-identical `403`s; an `admin` key → `404 unknown_release` naming the
  part that missed.
  Same matrix on the **`release_id` path** and on **`POST /evidence`**: a `product:<P>` key naming
  another product's release id and a nonexistent release id → two byte-identical `403`s; its own
  release id → filed; `admin` with a nonexistent id → `404`.
  **On implementation:** `TestBotIntakeAuthNonLeakMatrix`. All three sets of refusals are compared as
  **raw response bytes** (`bytes.Equal`), which is the only form the property has: a decoded struct
  cannot carry "these two answers are indistinguishable". Name road, `product:<P>` key — Q's name, a
  name registered nowhere, a name registered twice → three byte-identical `403 unauthorized`. The
  ambiguity is seeded by **removing Registry's uniqueness** and inserting the same Product name
  twice: with 000003 applied it is unreachable, which is the point of 000003, so the pre-index estate
  is the only place the third refusal can be produced. That removal also disables Registry's
  `ON CONFLICT` upserts, so the estate is registered **before** it, in a database of this test's own
  (hence one database per test, not one per suite).
  **The removal is introspected, not a list of names** (review ask): `registryUniqueness` queries
  `pg_index`/`pg_constraint` for every **non-primary-key** unique index on `products`, `projects` and
  `releases`, then drops each through `ALTER TABLE … DROP CONSTRAINT IF EXISTS` when a constraint owns
  it and `DROP INDEX IF EXISTS` when none does. Primary keys are excluded by `NOT i.indisprimary` —
  they are unique indexes too, they are on `id`, and they say nothing about whether a NAME is
  ambiguous. The reason is not only name drift: this test's subject IS the estate that has not taken
  000003, so pinning it to that migration's three index names would make it assert the shape of the
  thing it is meant to be independent of. On this checkout it finds and drops exactly the three plain
  indexes (logged by name in the test output), and **two post-conditions make the removal a fact
  rather than three statements**: the introspection is re-run and must come back empty, and the
  duplicate insert is counted back and must yield two rows — otherwise the "ambiguous" case would
  quietly be exercising the "no such product" refusal under the wrong name, which is the one failure
  mode that would look like a pass.
  **The byte-equality assertion was confirmed, not relaxed** (review ask): the refusal is a CONSTANT
  of exactly four fields — `detail` (the resolver's single constant), `reason: unauthorized`,
  `status: 403`, `title: intake refused` — with no correlation id, trace id or `intake_id` anywhere,
  which is what makes byte-equality achievable at all (`refuseUnauthorized` names no receipt on
  purpose, precisely so the bodies cannot differ on a field a caller can replay against). Verified by
  printing all three bodies. The test therefore also pins the **field set**: if a per-request field is
  ever added, this test names it as the cause instead of reporting an unexplained byte difference —
  and that would be a break of B3 to fix at the source, not a comparison to loosen.
  Beyond the task: two assertions that keep the `403`s from reading as a blanket answer. A project
  that does not exist **under the key's own product** is `404 unknown_release` naming it — so the
  confinement is not "everything is 403"; and the admin arm gets the answers the confined key is not
  shown — `404 unknown_release` naming the **product**, the **project** and the **version**
  respectively, `422 ambiguous_name` on the twice-registered name, and on the very triple that was
  `403` for the P key, **no refusal at all** (`201`, filed). `release_id` road: Q's release id and a
  nonexistent UUID → two byte-identical `403`s, its own release id → `201` filed, `admin` + unknown
  id → `404 unknown_release`. `POST /evidence`: the same two → two byte-identical `403 unauthorized`,
  its own → `201`.
  **One correction to the task's wording.** For `admin` + a nonexistent id the two doors do **not**
  answer alike, and asserting `404` on `POST /evidence` would assert a change this change did not
  make: that door has always met an unregistered subject with **`422 unknown subject release`**
  (EDR-EVIDENCE-01 D5), and B7 moved nothing for an unconfined caller — the one response B7 moved is
  a `product:<P>` key naming a nonexistent `release_id` (`404` → `403`, 3.4's note). The test asserts
  each door's own existing answer and says why at the call site.

- [x] **4.4 — Concurrency on a real node.** Two simultaneous `create_release=true` requests for the
  same unregistered version → **one** Release, two successful responses. This is the defect the
  constraints exist for and the one a single-threaded test cannot see.
  **On implementation:** `TestBotIntakeCreateReleaseConcurrent` — two goroutines released together on
  one channel, both posting the same triple + `create_release=true` + the same SBOM under a
  `product:<id>` key, every request bound to the test's own `context.WithTimeout` so a wedged node
  fails rather than hangs the suite. Asserted: both answered `201`/`200` with a `filed` receipt, both
  were given **the same** release id, **exactly one** reported `created=true` (which is what makes the
  other's `200` honest rather than a silent overwrite), and `GET /projects/{id}/releases` holds
  exactly one version. The database decides, not the application: both requests resolve the version as
  absent and both reach `UpsertRelease`, so what is under test is migration 000003's
  `registry_releases_project_version_key` and the `ON CONFLICT … DO NOTHING` read-back behind it.
  **The flag claim is backed STRUCTURALLY** (review ask): `created` is always present on a filed
  receipt — the edge fills in the explicit `false` when the use case did not create (D12) — so
  "exactly one true" is a claim about the two answers, not about which fields they happened to carry.
  It is nonetheless no longer the only evidence: the test now also counts the `evidence` rows and the
  distinct fingerprints for the release and requires **1 and 1**. Two rows with one `created=true`
  between them would be the worse bug, and the flags alone could not see it. The assertion was not
  loosened to "both may be deduped": that outcome is unreachable here (`ON CONFLICT (fingerprint) DO
  NOTHING` hands exactly one caller the insert), and accepting it would have let a genuine
  double-create pass.

- [x] **4.5 — `scripts/vm-verify.sh` stays truthful.** Confirm the read-only report still reads the
  EXPECTED migration version **from the migrations directory** (never a literal) now that Registry
  has a third migration and Evidence a fourth — the defect that left the systemd installer loading
  only the first registry migration.
  **Confirmed — the derivation was already correct, so NO behaviour changed.** It lives in
  `check_migration` (`scripts/vm-verify.sh`), and the line is quoted here verbatim so it can be
  audited without opening the file:

  ```sh
  want="$(find "$REPO_ROOT/$3" -name '*.up.sql' 2>/dev/null | sed 's#.*/0*\([0-9]*\)_.*#\1#' | sort -n | tail -1)"
  ```

  `$3` is the migrations directory the caller names, and the five call sites pass only a database, a
  bookkeeping table and a **directory path**. No version number appears anywhere in the script —
  grepped for `00000[0-9]`, `version <n>` and trailing numeric assignments; the only numeric literal
  in the whole file is `ISSUES=0`.
  Confirmed **by execution**, not by reading: run verbatim against this checkout the pipeline yields
  `registry=3`, `evidence=4`, `knowledge=10`, `governance=15`, `comms=6` — the integers
  `golang-migrate` stores in `version`. The `0*` prefix strips the leading zeros, which is also why
  Knowledge's `000010` reads as `10` and not `1`, and `sort -n` takes the numeric maximum rather than
  the last name alphabetically. So Registry's third and Evidence's fourth migration are picked up with
  no edit, and `vm-verify` flags a node still at `registry=2` / `evidence=3` as "running an older
  schema than this checkout".
  **One documentation-only change was made** (review ask: make 4.5 auditable from the diff rather
  than from a claim): six comment lines above that `want=` assignment now state the derivation rule at
  the point of use — the directory is the generator, the leading zeros are stripped so the value
  matches what `golang-migrate` stores, the sort is numeric, and the expression is POSIX BRE + POSIX
  sort so it behaves identically on the VM's GNU userland and on macOS. The existing section comment
  (why a literal must never appear here — the systemd-installer defect) is unchanged. **No executable
  line of the script is touched**, which the re-run above confirms.
  The same rule is now also **exercised in Go**: `botHighestMigration` in
  `tests/e2e/bot_intake_e2e_test.go` derives the expected version from the directory the same way and
  `botMigrate` asserts each schema landed on it — see 4.2's note.

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
