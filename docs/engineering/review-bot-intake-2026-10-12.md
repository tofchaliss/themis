# Design review — bot intake (Option 1) and one-SBOM-per-version

2026-10-12. Checked against `main` at `d1e2a32`. Read-only review; nothing changed.

The debate proposed: intake may create a release **version** (never a product or project) through a
Registry find-or-create, and Evidence refuses a second, different SBOM for a version that already
has one. The open gate was whether EDR-DELIVERY-01 M2-5 conflicts. It does.

## 1. M2-5 requires successive SBOMs on the SAME release — point 4 conflicts

`docs/engineering/decisions/EDR-DELIVERY-01.md` M2-5 (approved): "the comparison is **the new SBOM
against the immediately-previous SBOM of the SAME Release, by upload order**". RC-4: "on each new SBOM
produced by a rebuild … compares it against the previous SBOM for the same Product / Project /
Release". The `ci_rebuild` callback (N-M2 owner decision 5) has the Jenkins job upload the new SBOM
with a `product:<id>` key to that same release.

So a second, different SBOM on one release is not an accident of Evidence: it is the outward-actions
rebuild loop's designed input. Refusing it would break N-M2e (not yet built:
`TestSelectPreviousSBOM_ByUploadOrder`). Point 3 of the debate ("no design chose multiple SBOMs per
release") is therefore wrong for SBOMs too: EDR-INTAKE-01 D8 did not choose it, EDR-DELIVERY-01 did.

Three ways to resolve, for the owner:

| option | what | cost |
| --- | --- | --- |
| **A. Allow it only on the rebuild path** | a second SBOM is accepted when it carries a delivery intent id (the `ci_rebuild` callback's), refused otherwise (409) | intake learns one delivery concept; bots outside the loop still get the safe refusal |
| B. Drop the refusal | keep today's behaviour; rely on "rebuild = new version" as guidance only | stale-component findings stay possible (the `openssl 1.1` case) |
| C. Rebuild = new version | revise M2-5 so a rebuild registers a new version and compares across releases (`CompareReleases`) | reopens an approved EDR; the loop's "same Release" identity changes |

Recommendation: **A**. It keeps M2-5 as approved and still closes the gap for ordinary bots.

## 2. Registry has no uniqueness — duplicates are possible today

`internal/registry/adapters/store/migrations/000001_registry.up.sql`: `products(name)`,
`projects(product_id, name)` and `releases(project_id, version)` have **no UNIQUE constraint**.
Running `gf-upload-sbom.sh` twice with the same names already creates two products.

Name resolution in `cmd/evidence/main.go` (`registryReader`):

- `ProductIDByName` / `ProjectIDByName` abstain on more than one match, but report it as
  "no product named … is registered" — wrong message for an ambiguity.
- `ReleaseIDByVersion` returns the **first** match on a duplicate version instead of abstaining —
  inconsistent with the other two, and it silently picks one release.

A concurrency-safe find-or-create (debate point 2) needs `UNIQUE (project_id, version)` enforced by
the database with `INSERT … ON CONFLICT`. Adding that index fails if duplicates already exist, so a
census of the VM's `releases` (and `products`, `projects`) comes first.

## 3. What this means for the build order

1. Census the VM for duplicate products / projects / versions (read-only SQL).
2. Registry: unique constraints + idempotent find-or-create version endpoint; fix the
   ambiguity message and make `ReleaseIDByVersion` abstain on duplicates.
3. Intake: `create_release=true` resolves product + project by name (must exist) and asks
   Registry to find-or-create the version.
4. One-SBOM-per-version: only after the owner picks A, B or C above.
