# Proposal — phase3-outward-actions (EDR-DELIVERY-01)

> ## ⛔ N-M1a NEEDS TWO OWNER SIGN-OFFS BEFORE MERGE
>
> Both are must-asks under CLAUDE.md, neither can be self-granted, and **neither has been
> granted**. They are recorded here, at this change's front door, because an approval that lives
> only in a review thread is not a record. Mitigations are in place for both, so nothing unapproved
> is reachable on a default node — but the asks stay open.
>
> **On the absence of a `specs/` delta:** `phase3-*` changes carry none by design — proposal +
> design + tasks + the EDR *are* the source of truth, and `openspec validate` reporting "no deltas"
> is the expected result (CLAUDE.md, "OpenSpec is the system of record"). So the authoritative
> restatement of what N-M1a guarantees is `design.md` → **"Acceptance criteria as BUILT"**, not a
> spec file. Its absence is the convention, not an omission.
>
> | # | Ask | Mitigation in place | Record | Sign-off |
> |---|---|---|---|---|
> | 1 | **Add four Communication API routes** (`/delivery/intents`, `…/{id}`, `…/{id}/retry`, `…/{id}/cancel`) + two schemas to `api/communication.openapi.yaml` | **OFF BY DEFAULT.** `THEMIS_DELIVERY_OPERATOR_API=1` serves them; unset, all four answer `501` naming the switch. Recording, sending, retry and dead-lettering are NOT gated | `tasks.md` 2.0a · EDR D15 | ☐ `owner: ______ date: ______` |
> | 2 | **Dedup key is `origin_event_id`, not the `origin_event_seq` the step named** | None needed — it is strictly stronger (see below), but it IS a stated deviation from the step's wording | `tasks.md` 2.0b · EDR **D11** | ☐ `owner: ______ date: ______` |
>
> **Why ask 2 is not merely a convenience.** Four facts, each checkable in this tree:
> the kernel `Envelope` has no `seq` field and the reader never passes one to `Consumer.Handle`;
> `event_log.envelope_id` is `NOT NULL UNIQUE` and is commented as the bus's *own* dedup key;
> the publisher appends `ON CONFLICT (envelope_id) DO NOTHING`, so it is already idempotent on
> exactly that identity; and — decisively — with `THEMIS_BUS_DATABASE_DSN` unset (a documented dev
> mode) events arrive over the `/internal/governance-events` seam with **no bus and no seq in
> existence**, where a `BIGINT` seq column could only ever store `0` and would collapse every event
> of a type onto one intent. The step's column is not just more invasive to obtain; on that path it
> is wrong. The rejected alternative — widen the kernel `Envelope` to carry a transport cursor into
> every context — is itself a must-ask with a far larger blast radius.
>
> **If either is refused,** the exact revert is written out in `tasks.md` (2.0a, 2.0b). Neither
> revert touches the record, the workers or the dead-lettering.

## Why

Outward actions give Themis credentials that leave the estate (a delivery target calling back, CI
reporting, a mail relay). The moment one exists, "authenticated and not read-only" stops being an
acceptable definition of "may write": `auth.Principal.AuthorizeWrite()` grants a mutation to ANY
scope that is not `read`, and cannot confine `product:<id>` to that product's Findings because it
sees a principal and no resource.

So the authorization milestone comes first. **N-M0** makes the Governance write surface state, per
route, exactly which scopes may write it — before any scope exists that must not.

**N-M1a** then makes Themis act outward at all — by writing the action down first. A governance fact
crossing the bus becomes a durable *delivery intent*; separate per-channel workers try to send it,
retry with backoff and dead-letter when they run out of tries; and an operator can see the failures,
retry them or cancel them. The event reader NEVER sends, which is what keeps an unreachable Jira
from stalling the governance stream. Senders are fakes at this step: real Jira/CI/mail are M2/M3.

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

### N-M1a — delivery intents (D8–D17)

- **The record (D8, D9, D10, D11)** — `domain.DeliveryIntent` in the Communication context:
  `jira_issue` on `governance.finding_opened`, `email` (+ `ci_build` on harness evidence) on
  `governance.proposal_accepted`. The inbound consumer persists and returns; it holds no sender, so
  the event path cannot be stalled by an outward system. Each row is a snapshot — frozen lineage,
  deterministic payload bytes, sha-256 — written with the envelope claim in one transaction, deduped
  by a unique index on (origin event, event type, kind, destination).
- **The workers (D12, D13, D17)** — `adapters/delivery`: one `IntentWorker` per enabled kind over a
  one-method `Sender` port, retry with exponential backoff held as `next_attempt_at` on the row, and
  `DEAD_LETTER` once the attempts run out. Senders are `FakeSender`s (`success|fail|flaky`, no
  network); a disabled kind gets no worker rather than a refusing one.
- **The operator (D15, D16)** — four admin-only routes: list (filter by status/kind), read one with
  its append-only attempt history, retry a `DEAD_LETTER`/`CANCELLED` intent, cancel a `PENDING` one.
  Plus a startup posture line and a `delivery:` line in `scripts/vm-verify.sh`.

## Impact

N-M0: Governance HTTP adapter + its Registry client, the platform auth package, `cmd/authadmin`, and
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

N-M1a is confined to the Communication context: two migrations (`000006`/`000007`), a new domain
aggregate + use case, an `adapters/delivery` worker package, four new API routes (an API change —
asked and approved as part of this step), and new `THEMIS_DELIVERY_*` configuration on the
Communication node. **No existing event schema changes**, no cross-context import, and no other
context's behaviour changes.

## Not in this change

M2 (CI) and M3 (mail): no real Jira, SMTP or CI client exists — N-M1a's senders are fakes, and
`ci_build` intents stay dormant until `governance.proposal_accepted` states the accepted proposal's
evidence schema (M2's job). `delivery:callback` still exists and is still refused everywhere it must
be refused; what an outward target may call BACK into is undecided — N-M1a is outbound only, and
will be grilled in the runtime repository before it lands here.
