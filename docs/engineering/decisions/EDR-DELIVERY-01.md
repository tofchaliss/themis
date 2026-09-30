# EDR-DELIVERY-01 — Outward actions: authorization (N-M0) and delivery intents (N-M1a)

Status: **Accepted 2026-09-30** for N-M0 and for N-M1a. The decisions were grilled and locked with
the user in the `themis-ai-runtime` repository (`openspec/changes/outward-actions`, **D-N-1..6**
locked). This EDR records what those decisions require of THEMIS, so the Themis-side
implementation has a reason of record in this repository. Where they disagree, the runtime-side
design wins for runtime facts and this EDR wins for Themis domain facts.

Scope, by revision:

- **Revision 1 — N-M0, authorization** (D1–D7, below). The write surface states per route which
  scopes may write it, and `delivery:callback` is refused on every Governance write.
- **Revision 2 — N-M1a, the delivery intent** (D8–D17). The record, the isolated per-channel
  workers, and the operator's ability to see, retry or cancel a failed outward action. Senders are
  **fakes**: M2 (real CI) and M3 (real mail) are still NOT pre-decided here, and neither is any
  real Jira client. Sections written ahead of their grilling would read as decisions, which is
  exactly what the repository's rules mean by "the ADR is the reason of record".

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
2. **Any scope that was not `read` granted write — in EVERY context.** A typo (`produc:prod-1`),
   an invented grant (`governance:write`), or a new scope minted for something else entirely was
   indistinguishable from admin at any mutating endpoint, Governance's and everyone else's. A
   `delivery:callback` key would have inherited full mutating access across the estate on the day
   it was first minted, by doing nothing at all. Both halves are closed here: Governance decides
   explicitly (D1), and the floor the other contexts mount is closed to the known write scopes
   (D5).

## Decisions — N-M0 (authorization)

### D1 — Governance writes are authorized EXPLICITLY, per route (D-N-6)
Every Governance mutation calls `authorizeGovernanceWrite` before it acts. The rule, in order:

1. `delivery:callback` → **refused**, on every Governance write, unconditionally.
2. `admin` → allowed.
3. `product:<id>` → allowed **only** for the product that owns this Finding's release.
4. anything else (`read`, and any scope outside the closed vocabulary) → refused.

`AuthorizeWrite` is **retired as Governance's authorization decision**. It remains as the
method-based floor in `RequireWriteScope` for the other contexts — which is all it was ever able to
be, since a principal-only check cannot express a resource-scoped rule — and is itself closed to
`admin` / `product:<id>` there (D5).

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

### D5 — The scope vocabulary is CLOSED, at BOTH ends
`admin` · `read` · `product:<id>` · `delivery:callback` — and nothing else. `auth.KnownScope` is
the whole of it, and closure is enforced twice, because either half alone is a half-guarantee:

- **At minting** — `cmd/authadmin create-key` refuses an unknown scope, so no new key can carry
  one.
- **At reading** — `auth.Principal.AuthorizeWrite()` (the method floor behind
  `RequireWriteScope`, used by every context except Governance's explicit gate) returns true for
  `admin` or `product:<id>` **only**. It used to grant write on the first scope that was not
  `read`, which made a typo (`produc:prod-1`), an invented grant (`governance:write`) and a scope
  minted for some other purpose all indistinguishable from admin at every mutating endpoint in
  Knowledge, Evidence, Communication, Registry and Intelligence. Validating at mint time stops NEW
  keys; it does nothing about the ones already in the table, which is why the read side had to
  close too.

`product:<id>` carries the product's **id as registered** (a UUID in every current deployment);
the id is compared verbatim and never parsed, so no format is imposed on Registry.

**OPERATOR NOTE — audit existing keys before deploying this.** A key already in `api_keys` whose
scopes fall outside the vocabulary silently had write capability everywhere; it now has none
(reads are unaffected, and `admin` / `product:<id>` / `read` keys are unchanged). `authadmin` has
no list command, so audit over the `auth` database and re-mint anything unexpected:

```sh
psql "$THEMIS_AUTH_DATABASE_DSN" -c "SELECT id, name, scopes FROM api_keys WHERE revoked_at IS NULL ORDER BY created_at;"
```

Any row whose `scopes` is not a subset of {`admin`, `read`, `product:<id>`, `delivery:callback`}
loses write capability: re-mint it with a vocabulary scope (`create-key`) and revoke the old id.

### D5a — A refusal states the rule, never the estate
The 403 body names the scope rule that was not satisfied and nothing else: not the product that
owns the Finding, not the Registry endpoint, not a transport error. It is the one surface an
unauthorized caller is guaranteed to read, and "cannot resolve product for release X: dial tcp
10.0.3.7:8082: connection refused" answers questions the caller was refused permission to ask.
Every withheld detail goes to the shared logger instead (R1 — console + OTel from one call) with
the key id, Finding, release, rule and correlation id, so the operator sees strictly more than
before: whether to fix Registry or the key is a log question, not a caller's question. The
exception stays the 404: a Finding that does not exist is stated plainly, because answering 403
would tell an operator their own Finding belongs to somebody else.

### D6 — Authorization stays at the HTTP edge; the read surface is untouched
The check lives in the Governance HTTP adapter, never in `app` or `domain` (EDR-SECURITY-01 D1 —
scopes live in the platform/adapter rings). It is a WRITE rule and not a tenancy model: reads are
unchanged, so a product-scoped operator can still see the estate they are responsible for.
`RequireWriteScope` keeps its role unchanged — the explicit gate sits above the floor, it does not
replace it — and keeps blocking read-only keys on method exactly as before; what changed under it
is only which scopes count as write-capable at all (D5).

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

## Honest limits — N-M0

- **The Registry read seam sends no API key** (inter-service read clients are unauthenticated by
  design — EDR-SECURITY-01). On a deployment where the Registry node enforces inbound auth, the
  product hop answers 401, so product-scoped keys can write NOTHING there while `admin` keeps
  working. That is the fail-closed direction and is correct under D4, but it means product-scoped
  operation on an auth-enabled estate needs a credential for the read seam — deliberately NOT
  invented here (it is a security-model change, and M1 touches the same question).
- One extra Registry read per product-scoped write. Administrative writes are rare; no cache was
  added, because a cached authorization answer is a stale authorization answer.
- **Closing the read end of the vocabulary (D5) is a behaviour change outside Governance**, in the
  only direction available: a scope nobody can name is no longer a grant. It is stated as a limit
  because it is not free — a key minted with an unvetted scope stops being able to write, and the
  operator has to be told rather than discover it. The alternative was to leave a privilege
  escalation reachable by a typo.
- Nothing in this revision addresses outward DELIVERY itself (M1–M3). The scope exists and is
  refused everywhere it must be refused; what it will eventually be ALLOWED to do is undecided.

## Decisions — N-M1a (delivery intents)

N-M0 settled who may ask Themis to act outward. N-M1a settles what Themis DOES with such an
action: it writes it down, and then a worker tries to send it. All of it lands in the
**Communication** context (`internal/communication/{domain,app,adapters}`), because materializing a
governance fact into something addressed at the outside world is what that context already is.

### D8 — The event path RECORDS; it never SENDS (D-N-2)
Communication's inbound Governance consumer, on `governance.finding_opened` and
`governance.proposal_accepted`, persists delivery intents and returns. It holds no `Sender`, it
starts no goroutine, and it waits for no outcome. That is the milestone's load-bearing decision and
it is structural, not a discipline: there is no sender reachable from the ACL to be unreachable, so
an unavailable Jira **cannot** fail an envelope, halt the stream, or make the reader retry a
governance fact it has already applied. The intent is written inside the reader's inbox
transaction (EB-06), so the record and the envelope claim commit together — the recording half,
and only the recording half, is transactional with the event.

### D9 — The intent is a SNAPSHOT, frozen at record time (D-N-3)
Each row carries its immutable lineage (which envelope, which event type and time, which
Finding/Release/Faultline/CVE/proposal), a **deterministic materialized payload** rendered from
that lineage alone, and the sha-256 of those bytes. The payload is regenerable from the snapshot
and never from current state, and it is materialized in the DOMAIN
(`domain.NewDeliveryIntent` → `MaterializeDeliveryPayload`) rather than supplied by the caller: a
caller that could hand in its own bytes could hand in bytes that do not match the lineage, and the
hash would then certify a mismatch. A send that happens minutes or days later therefore delivers
what the fact said THEN. The alternative — re-reading the estate at send time — would quietly
deliver a different message than the one governance decided on.

### D10 — Forward-only, append-only, never deleted
`PENDING → DELIVERED | DEAD_LETTER | CANCELLED`, plus an operator retry that re-opens a terminal
row to `PENDING`. Every attempt appends a row to `delivery_attempts` (time, ok/fail, error) and a
retry **adds a chapter rather than erasing one** — the counter is reset, the history is not. The
state and its attempt row are written in ONE transaction, because an attempts counter with no
matching history row is precisely the state an operator cannot reason about. This is the Faultline
rule applied to outward actions: the audit of what Themis tried to do outside the estate is not a
cache, and a dead letter with no stated cause is as opaque as a dropped one.

### D11 — The dedup identity is the ENVELOPE ID, not the bus `seq`
The uniqueness guarantee asked for is one intent per (causing event, kind, destination), so that a
replay or a redelivery creates no second Jira ticket. The step's specification named
`origin_event_seq` for the first element; the implemented index uses `origin_event_id`. The reason
is a boundary fact: **the bus `seq` is deliberately not part of the wire `Envelope`**
(`internal/platform/eventbus/reader.go`) — it is the reader's cursor key, and a consuming context
never sees it. Carrying it here would have meant widening the kernel `Envelope`, a cross-cutting
change to every context, to obtain a value that has an exact one-to-one stand-in already in hand:
the envelope id, which `event_log` stores beside `seq` and on which the publisher is idempotent. The
guarantee is the one that was asked for; it is keyed on the identity that actually crosses the
context boundary. The dev `/internal/governance-events` seam posts envelopes with no id, where a
`type:subject@occurred_at` surrogate keeps distinct facts distinct — an empty key would collapse
every event of a type onto one intent.

### D12 — One worker per KIND, and the worker decides nothing
Each enabled kind gets its own goroutine, its own ticker and a queue scoped by kind. That is
isolation in both directions: from the bus (a worker only reads rows the reader already committed)
and between channels (a Jira outage fills the jira queue and leaves mail untouched). Retry and
dead-lettering are decided by the intent's own state machine in `domain`, not by the worker, so
"how many tries, how long a wait" has one answer rather than one per channel. **The schedule is
state on the row** (`next_attempt_at`, set from the backoff policy when the failure was recorded),
which is what lets the worker hold no timers: a test crosses a backoff by stepping an injected
clock and never sleeps, and a restarted node resumes the same schedule instead of retrying
everything at once. A send failure is not the pass's error — it is the intent's outcome. Only a
STORE failure stops a pass, because at that point the outcome cannot be recorded and sending the
next intent would risk acting without a record of having acted.

### D13 — The senders are FAKES, and every line they log says so
N-M1a ships `FakeSender` behind a one-method `Sender` port and no real Jira, SMTP or CI client. The
fakes touch no network at all. This is not a stub standing in for missing work: the milestone's
subject is the intent record, the worker lifecycle and the operator's ability to re-drive a
failure, and every one of those is fully — and more sharply — exercisable without a real endpoint's
flakiness in the loop. `THEMIS_DELIVERY_FAKE_{JIRA,EMAIL,CI}_MODE` (`success|fail|flaky`) exists so
the retry → dead-letter → operator-retry path can be walked on a real deployment; an unrecognized
value is read as `success`, because a typo must not turn a node's outward actions into silent
failures.

### D14 — No credential is ever stored on an intent (D-N-6)
`destination` is a governed NAME (one per kind at N-M1a, `"default"`). The sender resolves that name
to an endpoint and a secret held in its own configuration. The column is part of the dedup key
already, so multiple targets per kind can arrive later without a migration and without weakening
the uniqueness guarantee.

### D15 — The operator surface is ADMIN-ONLY, reads included

**Approval status: the API addition is an outstanding must-ask.** CLAUDE.md requires explicit owner
approval for an API change, and these four routes are new. They are implemented because the step
requires that a person be able to see, retry and cancel failed outward actions and this repository
has no other surface for that — but the approval is NOT on record. The ask, its alternatives, its
blast radius and the exact revert are written out in
`openspec/changes/phase3-outward-actions/tasks.md` item 2.0, which stays unchecked until an answer
exists. Nothing else in N-M1a depends on the routes: the record, the workers and the dead-lettering
stand without them.

`GET /delivery/intents`, `GET /delivery/intents/{id}`, `POST …/retry`, `POST …/cancel` — all four
require `admin`, not merely the node's write floor. Two reasons pointing the same way. A mutation
here **re-drives an action against a system outside the estate**, and the only non-admin write grant
in the closed vocabulary (D5) is `product:<id>`, which this context cannot confine: a
`proposal_accepted` intent's lineage names a Finding and no product, and D4's rule for an
indeterminate product is to refuse rather than guess. And the list is a cross-product view of the
estate's outward traffic, so serving it to a product-scoped key would hand over exactly the estate
detail D5a exists to withhold. The payload BYTES are not exposed: the operator needs to know what
was decided and how it went, and the hash already pins which bytes that was.

### D16 — Retry re-opens the terminal; Cancel withdraws the pending
`Retry` is permitted on `DEAD_LETTER` and `CANCELLED` only. Re-opening a `PENDING` intent would
reset the attempt counter of a send that may be in flight, and a `DELIVERED` one has already reached
the outside world — both are `409`, not `400`: the resource exists and its own state says no.
`Cancel` is permitted from `PENDING` and is a no-op success on an already-`CANCELLED` intent (the
caller asked for a state that already holds); `DELIVERED` cannot be un-sent and `DEAD_LETTER` has
already stopped, where cancelling would only relabel a failure as a decision. An unknown intent is
`404`.

### D17 — A disabled kind gets NO worker, not a refusing one
`THEMIS_DELIVERY_ENABLE_{JIRA,EMAIL,CI}=0` removes the worker. Its intents keep accumulating as
`PENDING`, stay visible on the operator list, and start moving the moment it is switched on. A
worker that refused instead would burn their attempt budget and dead-letter them while the
operator's own configuration was the cause. This is why the startup log states which kinds have a
worker beside the per-status counts: "nothing to send" and "nothing is sending" must not read the
same, and a dead-letter backlog under a disabled channel otherwise looks exactly like a healthy
idle node.

## Honest limits — N-M1a

- **`ci_build`'s trigger is structurally present and, on a real estate, dormant.** An acceptance
  fires a CI build only when the accepted proposal rested on `harness-execution/v1` evidence, and
  the frozen `governance.proposal_accepted.v1` payload does not state the proposal's evidence
  schema (`additionalProperties: false` over exactly FindingID, ProposalID, PositionVersion,
  OccurredAt). N-M1a changes no existing event schema, so today only the `email` intent is
  recorded. The decision, the kind, the payload and the tests exist and start working the day
  Governance's event carries the schema — which is M2's job, where the CI payload gains the
  artifact members it needs anyway. The alternative considered and rejected: asking Governance over
  HTTP what a finished event meant, i.e. putting a cross-context read on the event path to recover
  a fact the producer already knew.
- **The `ci_build` payload is minimal** — no artifact members. Full artifact capture is M2; N-M1a
  sets up the structure and the freezing.
- **One destination per kind.** Multiple Jira projects or mail audiences are a later step; the
  column and the dedup key already admit them.
- **A dead letter is where automation stops.** Nothing re-drives it on a timer — a person does. That
  is deliberate at this milestone (an automatic re-drive of an action against an outside system is
  the thing most worth being conservative about), and it is why the surface to see and retry
  failures ships in the same step as the failures themselves.
- **Delivery has no event of its own.** Nothing in Governance or Knowledge learns that an outward
  action was delivered or dead-lettered; the record and the operator API are the whole of the
  feedback. A `delivery.*` fact on the bus would be a new integration contract and is not needed to
  make the failures visible.

## Realizes

EDR-SECURITY-01 D1/D4 (the scope vocabulary as the authorization contract, now enforced at the
resource AND closed at both ends), EDR-HARNESS-01 D4 (the carried gap, closed), CONVENTIONS R1 (the
refusal's detail reaches console + OTel through the one shared logger; the workers and the fakes log
through the same package, and `domain`/`app` log nothing), CONVENTIONS R2 (every
`THEMIS_DELIVERY_*` knob is documented inline in `deploy/node.env.example`, and no secret is
inlined — or stored: D14), CON-0016 (traceability — the principal is already the recorded actor; now
it is also the authorization subject).
