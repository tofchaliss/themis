# Proposal — phase3-outward-actions (EDR-DELIVERY-01)

## Why

Outward actions give Themis credentials that leave the estate (a delivery target calling back, CI
reporting, a mail relay). The moment one exists, "authenticated and not read-only" stops being an
acceptable definition of "may write": `auth.Principal.AuthorizeWrite()` grants a mutation to ANY
scope that is not `read`, and cannot confine `product:<id>` to that product's Findings because it
sees a principal and no resource.

So the authorization milestone comes first. **N-M0** makes the Governance write surface state, per
route, exactly which scopes may write it — before any scope exists that must not.

Grounded in `docs/engineering/decisions/EDR-DELIVERY-01.md`, which records the Themis side of
decisions grilled and locked in the runtime repository (`openspec/changes/outward-actions`,
**D-N-6**). It supersedes EDR-SECURITY-01 D4's deferral of product-scope isolation and closes the
gap EDR-HARNESS-01 D4 carried forward.

## What changes

- **Explicit per-route write authorization (D1, D2, D7)** — `authorizeGovernanceWrite` in
  `internal/governance/adapters/http`: `delivery:callback` refused unconditionally → `admin`
  allowed → `product:<id>` allowed only for the Finding's own product → everything else refused.
  All nine Governance mutations gated. `AuthorizeWrite` retired as Governance's decision, retained
  as the method floor for the other contexts.
- **Resource resolution over the existing read seam (D3, D4)** —
  `registry.Client.ProductOfRelease`: Finding → release → `GET /releases/{id}` →
  `GET /projects/{id}` → product. Fail-closed: an indeterminate product refuses the write; a
  missing Finding is 404, not 403.
- **Closed scope vocabulary (D5)** — `auth.ScopeDeliveryCallback`, `auth.KnownScope`, and the
  explicit `Principal` helpers (`HasScopeExact`, `HasScopePrefix`, `HasProductScope`,
  `IsDeliveryCallback`); `cmd/authadmin create-key` mints `delivery:callback` and `product:<id>`
  and refuses anything outside the vocabulary.
- **The matrix as the guarantee** — every Governance write route × every scope
  {read, delivery:callback, product:wrong, product:correct, admin}, plus fail-closed and
  nothing-recorded-on-refusal tests.

## Impact

Governance HTTP adapter + its Registry client, the platform auth package, `cmd/authadmin`, and
Governance's composition wiring (one client, two seams). **No** API spec change, no migration, no
domain or app change, no change to the read surface, and no change to Knowledge, Evidence,
Communication or Registry behaviour.

Operationally: a `product:<id>` key can no longer write outside its product (the point), and on an
auth-enabled estate it cannot write at all until the Registry read seam carries a credential — an
honest limit recorded in the EDR, not worked around here.

## Not in this change

M1 (delivery), M2 (CI), M3 (mail). `delivery:callback` exists and is refused everywhere it must be
refused; what it will be ALLOWED to do is undecided and will be grilled in the runtime repository
before it lands here.
