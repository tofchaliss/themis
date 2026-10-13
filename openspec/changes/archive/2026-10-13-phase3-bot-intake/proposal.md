# Proposal — phase3-bot-intake (EDR-INTAKE-01, 2026-10-12 amendment)

## Why

`POST /api/v1/intake` shipped as one door for a **human with a runbook**. The next caller is a **CI
bot**, and the door does not fit it:

- **The bot has nowhere to put "register the release first".** D7 resolves `{product, project,
  version}` read-only, so a release that does not exist yet is a `404`. The product and the project
  are human-owned and already exist; **the version is new on every build**. So a pipeline either
  carries a second credential and calls Registry itself, or it hard-codes a release UUID a human
  captured once — which is how every build ends up filed against one Release, and how
  EDR-DELIVERY-01 **M2-5**'s baseline ("the immediately-previous SBOM of the SAME Release") stops
  meaning anything.
- **Registry's creates are check-then-insert and not unique at the database.** `products`,
  `projects` and `releases` carry a primary key on an opaque id and **no uniqueness on the name or
  version** (`000001_registry.up.sql`). Two concurrent bots registering the same version get **two
  Releases**, and a retry after a timeout gets a second one too. This is the same time-of-check /
  time-of-use shape D3 already fixed on the Evidence side, left unfixed one context over.
- **A name lookup that matches twice reports "not registered".** `registryReader` abstains on
  `len != 1` by returning an empty id (`cmd/evidence/main.go:392`), and the resolver turns that into
  `unknown_release` — "no product named X is registered" said about a product that is registered
  *twice*, which sends the operator hunting for a typo that is not there. `ReleaseIDByVersion` is
  worse: it returns the **first** exact match, silently picking a winner.
- **A filed document cannot say which pipeline run produced it.** Provenance records the tool, the
  image digest and the converted-source digest; the build that ran is unrecorded, so correlating an
  evidence row back to a CI run is a human reading timestamps.

## What changes

The owner's decisions are recorded in **EDR-INTAKE-01's 2026-10-12 amendment** as `B1`–`B6`; this
change implements them.

- **One request, one artifact (B1).** Unchanged in code — recorded as the contract. A bot sends the
  SBOM and the scan report as two requests, each retried on its own. No batch body, no
  multi-artifact transaction.
- **`create_release=true` (B2)** — accepted **only** with the whole `{product, project, version}`
  triple, and `400` when combined with `release_id`. Intake **never** creates a Product or a
  Project; it find-or-creates the **version** through Registry's own code, immediately before
  filing, so a refused submission creates nothing. D7 is narrowed, not reversed: the typo hazard it
  refused is specific to human-owned product and project names, and those stay read-only.
- **Authorization that does not leak existence (B3).** The order is authenticate → resolve the
  product → **authorize against that product** → resolve the project → find-or-create the version.
  A `product:<id>` key naming any other product gets the **same `403`** whether that product exists,
  does not exist, or is ambiguous; only `admin` is told `404 unknown_release`. This closes part of
  EDR-SECURITY-01 D4's product-scope deferral for the Evidence intake route, in the shape
  EDR-DELIVERY-01 N-M0 used for Governance.
- **Registry uniqueness enforced by the database (B4).** `products` unique on `lower(name)`,
  `projects` on `(product_id, lower(name))`, `releases` on `(project_id, version)` **exact**. The
  three creates become idempotent find-or-create via `INSERT … ON CONFLICT` — `201` new, `200`
  existing — so two concurrent callers get one row. The migration **refuses, naming the duplicates,**
  if any exist (the 2026-10-12 VM census found none, including case-insensitive collisions); it never
  merges or reassigns. The down migration drops constraints only. Name lookups **abstain and say
  *ambiguous***, `ReleaseIDByVersion` included.
- **Optional `build_id` (B5)**, ≤256 Unicode code points (never bytes; invalid UTF-8 refused), stored as a new provenance column beside
  `provenance_source` and `provenance_image_digest`, echoed on the receipt. **Not unique, and not
  used for dedup, correlation or current-SBOM selection.** A byte-identical retry dedups and keeps
  the **first** upload's `build_id`; the retry's value appears only on its own receipt. Over the
  bound is a named refusal, never a truncation.
- **Unchanged (B6):** same-bytes dedup; a different SBOM or report for the same release is filed as
  **new history** (M2-5 depends on it); `409 duplicate_other_release` across releases; D6's
  SBOM-before-report rule and its override.

## Impact

| area | change |
| --- | --- |
| `internal/registry/adapters/store` | one migration (three unique indexes + a refusing pre-flight), three `ON CONFLICT` upserts, three abstaining name-resolve queries |
| `internal/registry/app` | the three create use cases return `created bool`; `ErrAmbiguousName` |
| `api/registry.openapi.yaml` | **API** — `200` documented beside `201` on the three create routes; `created` on the responses |
| `internal/evidence/domain` | `Provenance.BuildID`; four new `RejectReason` values |
| `internal/evidence/app` | parameter validation, the authorize-then-create order, the `ReleaseProvisioner` port |
| `internal/evidence/adapters/{http,store,subjectref}` | the two new query parameters, `ErrAmbiguousName` mapping, one migration (`provenance_build_id` + the receipt's `build_id`) |
| `api/evidence.openapi.yaml` | **API** — `create_release`, `build_id`, `IntakeReceipt.build_id`, four enum values |
| `cmd/evidence/main.go` | the seam gains one write and the ambiguity sentinel |
| `scripts/gf-upload-sbom.sh`, `INSTALLATION.md`, `TESTING.md` | the bot road documented and driveable |

**No change** to Knowledge, Governance, Communication, the event bus, or any event contract. A filed
document is filed exactly as today, so everything downstream is untouched — including
EDR-DELIVERY-01 **M2-5** and the `ci_rebuild` callback.

**Scope is the `themis` repository only; `themis-ai-runtime` needs no change.**

## Non-goals

Each is deferred with its reason, so none is re-decided by reflex.

- **Current-SBOM ("effective inventory") selection and finding reconciliation.** B6 keeps every SBOM
  as history, which is correct and is also why a release can carry open Findings for components its
  newest inventory no longer lists. Filed as **"Current SBOM and finding cleanup"** in
  `docs/BACKLOG.md` behind an explicit design gate (its own EDR). Nothing here may fix it in passing.
- **`build_id` correlation.** It is a label; nothing reads it (B5).
- **Changing M2-5.** The baseline and the non-growing targeted set stand as written.
- **Longer receipt retention.** `THEMIS_INTAKE_RECEIPT_TTL` stays 30 days.
- **Product-scope isolation on the rest of the Evidence write surface.** `POST /evidence` and the
  `release_id` road keep the method-based `AuthorizeWrite` floor; widening that is its own decision.
- **Merging or repairing duplicate Registry rows.** The migration refuses; a merge re-points
  projects, releases, evidence, findings and positions, and that is an estate decision.

## Milestones

| # | milestone | contents |
| --- | --- | --- |
| **M1** | Registry is idempotent and honest | Group 1 — constraints, upserts, abstention, the `201`/`200` contract |
| **M2** | Intake is bot-friendly | Group 2 — `create_release`, the authorization order, `build_id` |
| **M3** | A bot can actually drive it | Group 3 — script + docs |
| **M4** | Verified on the estate | Group 4 — census re-run, the two-request bot test, gates green |

M1 ships on its own and is useful on its own (two concurrent registrations stop forking a Release).
M2 depends on M1's upsert and on nothing else.
