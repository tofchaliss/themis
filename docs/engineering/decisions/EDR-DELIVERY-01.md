# EDR-DELIVERY-01 — Outward actions: explicit write-scope authorization (N-M0)

Status: **Accepted 2026-09-30** for N-M0. The decisions were grilled and locked with the user in
the `themis-ai-runtime` repository (`openspec/changes/outward-actions`, **D-N-6** locked). This
EDR records what those decisions require of THEMIS, so the Themis-side implementation has a
reason of record in this repository. Where they disagree, the runtime-side design wins for
runtime facts and this EDR wins for Themis domain facts.

Scope of this revision: **N-M0 only — authorization.** The outward-actions milestones that follow
(M1 delivery, M2 CI, M3 mail) are deliberately NOT pre-decided here. This EDR records what has
been settled; sections written ahead of the grilling would read as decisions and are exactly what
the repository's rules mean by "the ADR is the reason of record".

Supersedes the deferral in **EDR-SECURITY-01 D4**'s realization note ("product-scope *isolation*
to a specific product is deferred … a follow-up") and closes the gap **EDR-HARNESS-01 D4**
carried forward ("`AuthorizeWrite` does not confine `product:<id>` to that product's Findings").

## Purpose

Outward actions give Themis credentials that LEAVE the estate: a delivery target calls back, a CI
system reports, a mail relay accepts. The moment such a credential exists, "authenticated and not
read-only" stops being an acceptable definition of "may write". N-M0 is the precondition for
every later milestone: the Governance write surface must state, per route, exactly which scopes
may write it — before any scope exists that must not.

## The defect this closes

`auth.Principal.AuthorizeWrite()` answers "may this principal mutate?" from the principal ALONE:

```go
if p.IsAdmin() { return true }
for _, s := range p.Scopes { if s != ScopeRead && s != "" { return true } }
```

Two consequences, both live until this change:

1. **`product:<id>` was not confined.** It granted write to every Finding in the estate, whatever
   product it belonged to. The function sees no resource, so it never could confine — the
   greenfield write routes key on a Finding, not a product (EDR-SECURITY-01 D4 realization note).
2. **Any scope that was not `read` granted write.** A typo (`produc:prod-1`), an invented grant
   (`governance:write`), or a new scope minted for something else entirely was indistinguishable
   from admin at a write. A `delivery:callback` key would have inherited full mutating access to
   Governance on the day it was first minted, by doing nothing at all.

## Decisions (Themis side)

### D1 — Governance writes are authorized EXPLICITLY, per route (D-N-6)
Every Governance mutation calls `authorizeGovernanceWrite` before it acts. The rule, in order:

1. `delivery:callback` → **refused**, on every Governance write, unconditionally.
2. `admin` → allowed.
3. `product:<id>` → allowed **only** for the product that owns this Finding's release.
4. anything else (`read`, and any scope outside the closed vocabulary) → refused.

`AuthorizeWrite` is **retired as Governance's authorization decision**. It remains as the
method-based floor in `RequireWriteScope` for the other contexts, which is all it was ever able to
be: a principal-only check cannot express a resource-scoped rule.

### D2 — The refusal of `delivery:callback` is on the SCOPE, not on what is missing beside it
A key carrying `delivery:callback` is refused even if it also carries `admin` or the right product
grant. A credential handed to an outward target must not double as a governance identity, however
it was minted. The same scope is excluded from `AuthorizeWrite`, so minting it cannot hand
mutating access to Knowledge, Evidence, Communication or Registry either — that hole would be
opened by the SCOPE EXISTING, not by using it, and is closed in the same change that creates it.

### D3 — Confinement resolves the resource: Finding → Release → Product
The route loads the Finding from Governance's own store, reads its `release_id`, and resolves the
owning product over the **Registry read API** (`GET /releases/{id}` → `project_id`,
`GET /projects/{id}` → `product_id`). Two hops, one existing read seam, no new endpoint, no
cross-context import, no schema change. The product is never stored in Governance: duplicating
Registry's identity chain would create a second truth that can drift.

### D4 — Fail closed on an indeterminate product, fail open nowhere
If the product cannot be established — Registry unreachable, the seam not wired on this node, a
release Registry does not know, a blank hop — a product-scoped key is **refused (403)**. This is
the deliberate OPPOSITE trade from the blast-radius read on the same client, which fails open to
1.0×: over-stating a triage number is a nuisance, granting a write to the wrong product is a
breach. `admin` needs no resolution and is unaffected, so a node without the Registry seam stays
operable.

A write to a Finding that does not exist is **404, not 403**. The resource is absent; answering
403 would tell an operator that their own Finding belongs to someone else.

### D5 — The scope vocabulary is CLOSED
`admin` · `read` · `product:<id>` · `delivery:callback` — and nothing else. `auth.KnownScope` is
the whole of it, `cmd/authadmin create-key` validates against it and refuses an unknown scope at
mint time. Enforcing it at minting is the only place it can be enforced: a stored scope is read by
every node afterwards, and an unknown scope must not be storable and then read as authorization.
`product:<id>` carries the product's **id as registered** (a UUID in every current deployment);
the id is compared verbatim and never parsed, so no format is imposed on Registry.

### D6 — Authorization stays at the HTTP edge; the read surface is untouched
The check lives in the Governance HTTP adapter, never in `app` or `domain` (EDR-SECURITY-01 D1 —
scopes live in the platform/adapter rings). It is a WRITE rule and not a tenancy model: reads are
unchanged, so a product-scoped operator can still see the estate they are responsible for.
`RequireWriteScope`'s read-only block is left exactly as it was — the explicit gate sits above the
floor, it does not replace it.

### D7 — Why per-route and not middleware
The decision needs the RESOURCE, and only the route knows which Finding is being written.
Re-deriving it by parsing paths in middleware would duplicate the router — a second, silent
routing table whose disagreement with the first is invisible. The cost is one guard line per write
handler; the test matrix (every write route × every scope) is what keeps a newly added route from
shipping ungated.

## What is gated

All nine Governance mutations: raise proposal · accept · reject · commission · withdraw
commission · recommend position · resolve · reopen · archive. `recommend_position` is included
because it RECORDS an advisory AI proposal — it mutates the Finding even though a human asked a
model a question.

## Honest limits

- **The Registry read seam sends no API key** (inter-service read clients are unauthenticated by
  design — EDR-SECURITY-01). On a deployment where the Registry node enforces inbound auth, the
  product hop answers 401, so product-scoped keys can write NOTHING there while `admin` keeps
  working. That is the fail-closed direction and is correct under D4, but it means product-scoped
  operation on an auth-enabled estate needs a credential for the read seam — deliberately NOT
  invented here (it is a security-model change, and M1 touches the same question).
- One extra Registry read per product-scoped write. Administrative writes are rare; no cache was
  added, because a cached authorization answer is a stale authorization answer.
- Nothing in this revision addresses outward DELIVERY itself (M1–M3). The scope exists and is
  refused everywhere it must be refused; what it will eventually be ALLOWED to do is undecided.

## Realizes

EDR-SECURITY-01 D1/D4 (the scope vocabulary as the authorization contract, now enforced at the
resource), EDR-HARNESS-01 D4 (the carried gap, closed), CON-0016 (traceability — the principal is
already the recorded actor; now it is also the authorization subject).
