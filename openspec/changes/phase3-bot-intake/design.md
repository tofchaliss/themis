# Design — phase3-bot-intake

Source of truth: **`docs/engineering/decisions/EDR-INTAKE-01.md`, the 2026-10-12 amendment
("Bot-friendly intake"), decisions `B1`–`B6` and its status-code table.** Where this document and
the EDR disagree, the EDR wins. This change carries **no `specs/` deltas** (phase3 convention —
archive with `openspec archive phase3-bot-intake --skip-specs -y`).

Related records: EDR-SECURITY-01 **F1/D4** (inbound-edge auth, `product:<id>`), EDR-DELIVERY-01
**M2-5** + N-M0 (the per-release SBOM baseline; the product-scoped write pattern), EDR-EVIDENCE-01
**D3/D8** (content addressing, the cross-release `409`), EDR-KERNEL-01 **D1** (Registry owns
identity).

## 1. What moves where

Nothing new is created as a package, a service or a ring. Three rings of two existing contexts
change, plus the composition root that already wires both.

```text
      bot (CI)
        │  POST /api/v1/intake?product=&project=&version=&create_release=true&build_id=…
        ▼
┌──────────────────────── Evidence node (:8081) ────────────────────────┐
│  adapters/http/intake.go   params → validate (B2 exclusivity, B5 bound)│
│  platform/auth             Principal.AuthorizeProduct  ── B3 step 3    │
│  app/intake.go             step order; nothing filed until the end     │
│  adapters/subjectref       Resolve (read-only) + Provision (one write)  │
│  domain/evidence.go        Provenance.BuildID                          │
└────────────────┬───────────────────────────────────────────────────────┘
                 │  cmd/evidence composition root — the ONLY assembler
                 ▼
┌──────────────── registry schema, co-located in the `evidence` DB ──────┐
│  registry/adapters/store   ON CONFLICT upserts · abstaining resolves    │
│  registry/app              find-or-create; ErrAmbiguousName             │
│  migrations/000003         three unique indexes + a refusing pre-flight │
└────────────────────────────────────────────────────────────────────────┘
```

The import direction is unchanged (`domain ← app ← adapters`), no bounded context imports another,
and `cmd/evidence` stays the only place the two are assembled — exactly the standing arrangement that
makes today's `registryReader` legal.

## 2. The seam gains ONE write, and the wall is replaced rather than removed

D7's sentence — "a write from Evidence into Registry is neither an event nor a read" — was the wall.
B2 narrows it, so the replacement has to be structural, not a comment:

```go
// internal/evidence/adapters/subjectref

// ErrAmbiguousName is the seam's abstention: the name matched more than one row, so
// picking one would invent the caller's intent. Owned HERE, not by Registry, so no
// registry type or error value crosses the seam (primitives only).
var ErrAmbiguousName = errors.New("subjectref: name is ambiguous")

type Registry interface {               // unchanged shape, documented abstention
    ReleaseExists(ctx context.Context, releaseID string) (bool, error)
    ProductIDByName(ctx context.Context, name string) (string, error)
    ProjectIDByName(ctx context.Context, productID, name string) (string, error)
    ReleaseIDByVersion(ctx context.Context, projectID, version string) (string, error)
}

// ReleaseProvisioner is the ONE write. It can create a version under an EXISTING
// project and nothing else — there is no product or project verb to reach for, which
// is what keeps B2's bound structural instead of conventional.
type ReleaseProvisioner interface {
    FindOrCreateRelease(ctx context.Context, projectID, version string) (id string, created bool, err error)
}
```

Three properties, each a way this could have gone wrong:

- **It cannot create a Product or a Project**, because the interface has no such method. A future
  widening is a visible interface change, not a new argument.
- **Registry still owns the invariant.** `FindOrCreateRelease` goes through Registry's own app
  service and store, so the uniqueness rule, the id generation and the `created` answer are
  Registry's. Evidence learns an id; it does not learn how Releases work.
- **`cmd/evidence` is still the only assembler**, and it is where `registryapp.ErrAmbiguousName` is
  translated into `subjectref.ErrAmbiguousName`. Nothing but primitives and this context's own
  sentinel crosses.

An architecture test asserts the seam exposes no second write and that no `internal/evidence/…`
package imports `internal/registry/…`.

## 3. Step order — and why the create is late

**The authoritative order is EDR-INTAKE-01 amendment B7** (revised at the Gate A review). It is
restated here; if the two ever differ, the EDR wins. It keeps the **implemented** D5 order and
inserts the new steps into it.

```text
 0 authenticate + method write floor            (unchanged)
 1 PARAMETER VALIDATION   ← new, no body needed: create_release ⟂ release_id, triple complete,
                            build_id ≤ 256 code points and valid UTF-8
 2 size bound                                    (unchanged)
 3 identify the body (D5a)                       (unchanged)
 4 RESOLVE + AUTHORIZE, read-only, BOTH paths   ← new authorization
     name path:   product by name → AuthorizeProduct → project by name → version lookup
     release_id:  release → project → owning product → AuthorizeProduct
 5 validate input + convert (D5b, D3)            (unchanged)
 6 validate output (schema_invalid, empty_report) (unchanged)
 7 D6 SBOM-before-report                         (unchanged; a version still to be created has none)
 8 FIND-OR-CREATE the version  ← new, and deliberately HERE, not at step 4
 9 file + receipt — the only step that writes evidence (unchanged)
```

**Why step 8 and not step 4.** B3 says "nothing is created on any refusal", and that has to hold for
the whole request, not only the authorization part. If the create sat with resolution, every later
border refusal — `schema_invalid`, `source_invalid`, `empty_report`, `no_inventory_for_release` —
would leave an empty Release behind, and a bot retrying a malformed report would mint one per
attempt. Deferring the create also preserves D5's **first-failure-wins** precedence exactly: an
invalid-and-early report still reports `schema_invalid`, never something about release creation, so
`TestIntakeOrdering`-shaped assertions keep holding unchanged.

**The one refusal that can follow a create** is `409 duplicate_other_release`, because it is
discovered by the database at the evidence insert (EDR-INTAKE-01 D3's dispatch path). The created
version is retained — it is a legitimate Release with no evidence yet — and a corrected retry reuses
it, because step 8 is idempotent. Recorded in the EDR as an honest limit; **not** something to work
around with a pre-insert lookup, which would reintroduce the TOCTOU race D3 removed.

**Where parameter validation sits.** Step 1, before the size bound: it needs no body and has no
side effect. It can only change the answer for a request that uses the new parameters (an oversized
body with a malformed `build_id` now reports `build_id_invalid`), so no existing request's answer
moves. Task 2.4 asserts this order with a test, so it is a decision rather than an accident of code
layout.

**Authorization on the `release_id` path, and the old door.** Step 4 authorizes the resolved
product on **both** paths (EDR B7): a `product:<P>` key naming another product's release **or** a
release that does not exist gets the same `403`; `admin` keeps `404`. `POST /evidence` gains the
same ownership check, so the old door is not a bypass. The seam needs one more read for it —
`ProductOfRelease(releaseID) (productID string, err error)` on `subjectref.Registry` — and it is a
read, so B2's "exactly one write" property is unchanged.

## 4. The non-leak property, implemented as one branch

B3 is easy to lose by writing three refusals in three places. One branch, fail-closed:

```go
// after step 4, before step 6
if !principal.AuthorizeProduct(productID) {   // admin ⇒ true; product:<id> ⇒ id match
    return reject(ReasonUnauthorized, "the key is not authorized for this product")
}
```

and the three product-lookup outcomes a product-scoped key must not distinguish are collapsed
*before* that branch, not inside it:

| step 4 outcome | `admin` | `product:<P>` |
| --- | --- | --- |
| resolves to `P` | continue | continue |
| resolves to another product | continue (admin may) | `403` |
| resolves to nothing | `404 unknown_release` naming the product | `403` |
| matches >1 row | `422 ambiguous_name` | `403` |

So the product-scoped key's three `403`s must be **byte-identical** — same status, same `reason`,
same `detail` string, no `X-`header difference, no timing branch that does extra work in one case. A
test asserts the three responses are equal as bytes; asserting "all three are 403" would pass while
the detail text leaked the answer.

Once a key is authorized for the product, steps 6–7 give it the same answers `admin` gets — there is
nothing left to leak, because the key already holds authority over that product.

**Auth disabled** (`THEMIS_AUTH_DATABASE_DSN` unset): no principal, so intake treats the caller as
`admin`, the same posture every other route on that node has. `THEMIS_AUTH_REQUIRED=1` remains the
production guard. `create_release` does not touch the auth switch.

## 5. Registry: constraints, upserts, and two SQL traps

**The three constraints**, created as **named** unique indexes because `ON CONFLICT` inference and
the error-dispatch path both need the names to be part of the contract (EDR-INTAKE-01 D3's trap #2,
one context over):

```sql
CREATE UNIQUE INDEX registry_products_name_key           ON products (lower(name));
CREATE UNIQUE INDEX registry_projects_product_name_key   ON projects (product_id, lower(name));
CREATE UNIQUE INDEX registry_releases_project_version_key ON releases (project_id, version);
```

Case-folding is asymmetric on purpose (B4): product and project names are human-typed labels, so
`"OAMP"` and `"oamp"` are one row; a **version** is a machine build string whose case Themis does not
own, so release uniqueness is **exact**. Folding versions would merge two builds.

**Trap 1 — an expression index needs the expression restated.** `ON CONFLICT (name)` does **not**
infer an index on `lower(name)`; the statement must read `ON CONFLICT (lower(name))`, exactly as D3's
partial index needed its `WHERE` clause restated. Without it the statement fails outright, which is
the good failure — but only if a test exercises the conflict path rather than the happy path.

**Trap 2 — the generated id is discarded on a conflict.** The upsert is

```sql
INSERT INTO products (id, name) VALUES ($1, $2)
ON CONFLICT (lower(name)) DO NOTHING
RETURNING id
```

and `ErrNoRows` means "someone else won" → read the winner back by `lower(name)` and return it with
`created=false`. So the service must **not** publish, log or return the id it generated before the
insert resolves, and a caller must never assume the id it sees is the one this process minted. The
stored **casing is the first caller's** (B4): a later `"oamp"` gets the existing `"OAMP"` row and no
indication its own spelling was not used.

**The migration refuses; it never repairs.** The up migration's first statement is a pre-flight that
`RAISE EXCEPTION`s with the offending groups named (capped list, counts included) if any duplicate
exists, so the failure tells an operator **which rows** to resolve rather than that "the migration
failed". It never merges or reassigns: a merge re-points projects, releases, evidence, findings and
positions, which is an estate decision. The **down** migration drops the three indexes and **touches
no data**.

**The pre-flight cannot be raced (Gate A review, revision 2).** A duplicate inserted after the
pre-flight query but before `CREATE UNIQUE INDEX` would turn the named refusal into a bare `23505`
from the index build. So the migration runs as **one explicit transaction**. Its **first statement after `BEGIN`** is
`LOCK TABLE products, projects, releases IN SHARE ROW EXCLUSIVE MODE`. That mode blocks every
concurrent `INSERT`/`UPDATE`/`DELETE` on the three tables (it conflicts with `ROW EXCLUSIVE`) while
still allowing reads. Writes are therefore quiesced from the pre-flight through the last index, and
released at commit. (The mode also conflicts with itself, so two transactions that take it
serialize; but what stops two migration **runners** from both applying `000003` is golang-migrate's
own Postgres advisory lock and its `registry_schema_migrations` version row, not this table lock.) The indexes are built
**without** `CONCURRENTLY` (which cannot run inside a transaction); the lock is held for the
duration of the pre-flight and three index builds, **expected to be brief on the current registry
size** (it depends on table size, index-build time and database load), and a Registry write that
arrives meanwhile waits and then proceeds rather than failing.
The file says `BEGIN;` … `COMMIT;` explicitly, so the transaction boundary does not depend on how
the driver sends it. Under these conditions no maintenance window is required for this migration; the 2026-10-12 census is evidence the
refusal will not fire on the VM, not the mechanism that makes it safe.

**Abstention.** The three name-resolve queries move into `registry/adapters/store` (where integration
tests and the 80% store tier live) and return `app.ErrAmbiguousName` on `>1`, an empty id on `0`.
`cmd/evidence`'s `registryReader` becomes thin delegation plus the sentinel translation.
`ReleaseIDByVersion` stops scanning for the first exact match and abstains the same way. Both
abstentions survive the constraints that make `>1` unreachable, deliberately: an un-migrated estate
still has the old shape, and a guard that holds only because of an index disappears with the index.

## 6. `build_id`: storage, echo, and the dedup asymmetry

| where | field | note |
| --- | --- | --- |
| `evidence.provenance_build_id` | `TEXT NOT NULL DEFAULT ''` | **new column**, beside `provenance_source` / `provenance_image_digest` |
| `intake_receipts.build_id` | `TEXT NOT NULL DEFAULT ''` | so `GET /intake/{id}` echoes it after the fact, not only on the synchronous response |
| `domain.Provenance.BuildID` | `string` | data, never a modeled entity — the same standing as the image digest (EDR-KERNEL-01 D2) |
| `IntakeReceipt.build_id` | **API** | echoed |

**The asymmetry is the design, not a bug to discover.** A byte-identical retry dedups and the
evidence row keeps the **first** upload's `build_id` — `ON CONFLICT … DO NOTHING` does not update, and
Evidence is immutable (CON-0007) so it must not. The retry's `build_id` appears on **its own
receipt**. Therefore a receipt's `build_id` and the filed document's `build_id` can differ: a receipt
records an **attempt**, the evidence row records what was **filed**. A test asserts exactly this pair
of values rather than asserting they match.

Nothing reads `build_id` to decide anything — not dedup, not correlation, not current-SBOM
selection. A test asserts two submissions differing **only** in `build_id` produce **one** evidence
row, which is the inertness stated as an assertion.

The bound is **256 Unicode code points**, counted with `utf8.RuneCountInString` on the decoded
value (never `len`), matching OpenAPI's `maxLength`; invalid UTF-8 is refused by the same reason.
Over the bound or malformed is `400 build_id_invalid`, **not** a truncation: D13's reasoning about invalid
UTF-8 applies unchanged — a value silently altered is not the value the caller recorded, and
provenance is the worst place to discover that later.

## 7. The reason enum grows by four

`create_release_conflict` (400) · `incomplete_release_triple` (400) · `ambiguous_name` (422) ·
`build_id_invalid` (400).

D11's discipline applies in full: the Go enum, the OpenAPI `RejectReason` enum,
`TestIntakeReasonTaxonomyIsClosed` and every consumer that renders an intake reason (the dashboard's
upload path) grow **in the same change**. #116's cost — a consumer knowing 6 of 15 reasons asserting
"no reason given" for the other nine — is the reason this is a gate and not a cleanup.

`reason` and `detail` stay **two fields**, never concatenated (D9/D11, the 2026-09-22 lesson).

## 8. What is deliberately NOT done

- **M2-5 is untouched.** Baseline = the immediately-previous SBOM of the same Release by upload
  order; the targeted set does not grow mid-cycle. B6 is what it rests on, and this change
  strengthens it (releases accumulate their own SBOMs instead of a pipeline filing every build
  against one hard-coded Release) without changing a word. The `ci_rebuild` callback path is not
  touched: no delivery kind is added, removed or re-timed.
- **Current-SBOM selection and finding reconciliation** — out of scope, behind a design gate, filed
  as **"Current SBOM and finding cleanup"** in `docs/BACKLOG.md`. This change must not partially
  implement it; a half-built effective-inventory rule is worse than the known gap.
- **`build_id` correlation**, **longer receipt retention**, **product-scope isolation on the rest of
  the Evidence write surface**, and **merging duplicate Registry rows** — each with its reason in
  `proposal.md`'s Non-goals.

## 9. Stack and gates

Stack is unchanged — see `docs/engineering/STACK.md`. No new dependency, package, service or
directory.

Gates, every group: `make check` locally (CI runs `make check-ci`), and each group ends by making
**`make vet-tags`** green — a tagged file is invisible to the default build and rots silently
(`llm_e2e_test.go`, 2026-08-07). Specifically applicable here:

| gate | what it catches for this change |
| --- | --- |
| `make vet-tags` | the new `-tags=integration` store tests and the `-tags=e2e` bot test compiling at all |
| `make clean-arch` | a cross-ring test placed in the wrong directory (it scans test files too) |
| `make arch-test` | `internal/evidence` importing `internal/registry`; the seam exposing a second write |
| `make coverage` | `registry/adapters/store` (80%), `registry/app` (100%), `evidence/{domain,app}` (100%), `evidence/adapters/{http,store,subjectref}` (90%) — all already registered in `scripts/check-coverage.sh` |
| `make generate-api-registry` / `-evidence` | handlers are generated, never hand-edited |
| migration up/down reversibility | a task gate per CLAUDE.md, for both new migrations |

## 10. Risks

| risk | handling |
| --- | --- |
| the uniqueness migration blocks an upgrade on a duplicate-bearing estate | Group 4's census **re-run before** the migration ships; the migration names the rows so the operator can resolve them; refuse-don't-repair is the stated decision (B4) |
| the three `403`s diverge in wording and leak existence | asserted as **byte equality**, not as three status codes |
| a refused submission mints an empty Release | the create is step 9, after every border check; the one exception (`409`) is recorded as an honest limit |
| `create_release` quietly becomes a general create-if-missing | the seam has no product/project verb; an architecture test asserts it |
| the enum grows and a consumer renders "no reason given" | the taxonomy guard test + the dashboard in the same change (§7) |
