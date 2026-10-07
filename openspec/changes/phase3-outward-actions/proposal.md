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
  as the method floor for the other contexts. A refusal states the rule only — the product that
  owns the Finding and any Registry failure go to the shared logger, never the 403 body (D5a).
- **Resource resolution over the existing read seam (D3, D4)** —
  `registry.Client.ProductOfRelease`: Finding → release → `GET /releases/{id}` →
  `GET /projects/{id}` → product. Fail-closed: an indeterminate product refuses the write; a
  missing Finding is 404, not 403.
- **Closed scope vocabulary, at BOTH ends (D5)** — `auth.ScopeDeliveryCallback`,
  `auth.KnownScope`, and the explicit `Principal` helpers (`HasScopeExact`, `HasScopePrefix`,
  `HasProductScope`, `IsDeliveryCallback`); `cmd/authadmin create-key` mints `delivery:callback`
  and `product:<id>` and refuses anything outside the vocabulary; and `AuthorizeWrite` — the floor
  every OTHER context mounts — is closed to `admin` ∪ `product:<id>`. It used to grant write on any
  scope that was not `read`, so a typo'd or invented grant was indistinguishable from admin at
  every mutating endpoint in Knowledge, Evidence, Communication, Registry and Intelligence.
  Validating at mint time stops new keys; it does nothing about the ones already in the table.
- **The matrix as the guarantee** — every Governance write route × every scope
  {read, delivery:callback, product:wrong, product:correct, admin}, plus fail-closed and
  nothing-recorded-on-refusal tests.

## Impact

Governance HTTP adapter + its Registry client, the platform auth package, `cmd/authadmin`, and
Governance's composition wiring (one client, two seams; `Wire` now takes the shared logger). **No**
API spec change, no migration, no domain or app change, and no change to the read surface anywhere.
The other contexts' write paths change in exactly one way — their floor no longer honours a scope
outside the vocabulary — which is the point of D5 rather than a side effect.

Operationally, three things:

1. A `product:<id>` key can no longer write outside its product (the point), and on an auth-enabled
   estate it cannot write at all until the Registry read seam carries a credential — an honest
   limit recorded in the EDR, not worked around here.
2. **A key already minted with a scope outside the vocabulary loses write capability everywhere.**
   Audit before deploying: `SELECT id, name, scopes FROM api_keys WHERE revoked_at IS NULL;` (see
   EDR-DELIVERY-01 D5). Reads are unaffected; `admin`, `read` and `product:<id>` keys are unchanged.
3. A 403 on a Governance write is less informative to the caller by design; the corresponding log
   line is more informative than anything that existed before.

## Added 2026-10-01 — the remediation cycle, recorded (documentation only)

The owner restated the outward-actions workflow as a loop: SBOM uploaded under Product / Project /
Release / SBOM id → Themis lists its vulnerabilities → a Jira ticket tracks the fix → a Jenkins
build produces a new image and a new SBOM under a new SBOM id for the same Release → Themis
compares new against previous and updates the ticket → the result goes out by mail → repeat until
fixed or the rebuild limit is reached, then stop and tell a person.

Grilled runtime-side as **D-N-8..D-N-12** and recorded here as **EDR-DELIVERY-01 Revision 2**
(RC-1..RC-8), with the acceptance block in `design.md` and the doc-only steps in `tasks.md`
(Group 5). What it settles:

- **Trigger (RC-1)** — the cycle starts on *evaluation complete* for the Release, not on SBOM
  receipt. A Themis-owned pub/sub notification may carry that signal to the AI Harness; its
  transport, event names, delivery semantics, subscriber auth and owning context are deferred to a
  dedicated EDR + API change.
- **Jira (RC-2)** — one ticket per Release, severity counts for all four levels, CVE ids listed
  for Critical and High only.
- **`ci_rebuild` (RC-3)** — a new, policy-gated delivery kind, **approved as a decision of record,
  not implemented**. Its callback must carry the new SBOM id and the image digest. **Existing
  `ci_build` semantics are preserved unchanged**: it still carries the accepted change artifact and
  still follows the `proposal_accepted` path.
- **Comparison and mail (RC-4, RC-5)** — Jira updates and mail happen only after the new-vs-previous
  SBOM comparison, never from the build callback alone.
- **Loop control (RC-6)** — default maximum 2 rebuild attempts per Release, operator-configurable;
  exhaustion stops the loop and tells a person; Findings are never auto-resolved.
- **Ownership (RC-7)** — Themis owns security truth, every outward effect and the loop; the harness
  subscribes and nothing more.

**Scope: documentation only.** No code, API spec, schema, migration or generated-handler change
lands with it; `make check` is run to prove exactly that. **N-M0 is preserved in full** (RC-8):
explicit per-route write-scope authorization, `delivery:callback` refused on every Governance
write, `product:<id>` confined to its product, closed scope vocabulary — the cycle adds no scope
and relaxes nothing.

## Not in this change

M1 (delivery), M2 (CI), M3 (mail) — including every mechanism Revision 2 describes. The
remediation cycle is recorded, not built: `ci_rebuild` has no code, the valuation-complete
notification has no transport, and the max-attempts knob has no name yet. `delivery:callback`
exists and is refused everywhere it must be refused; what it will be ALLOWED to do is undecided and
will be grilled in the runtime repository before it lands here.
