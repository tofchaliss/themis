# EDR-DELIVERY-01 — Outward actions: explicit write-scope authorization (N-M0)

Status: **Accepted 2026-09-30** for N-M0; **Revision 2 (2026-10-01) — remediation cycle, accepted
as a decision of record, NOT implemented**; **Revision 3 (2026-10-02) — N-M1a delivery intents,
IMPLEMENTED** (see the Revision 3 section at the end: intents are persisted and sent by workers
against FAKE senders; the real Jira/mail senders and the rebuild loop are later milestones). The decisions were grilled and locked with the user in
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
2. **Any scope that was not `read` granted write — in EVERY context.** A typo (`produc:prod-1`),
   an invented grant (`governance:write`), or a new scope minted for something else entirely was
   indistinguishable from admin at any mutating endpoint, Governance's and everyone else's. A
   `delivery:callback` key would have inherited full mutating access across the estate on the day
   it was first minted, by doing nothing at all. Both halves are closed here: Governance decides
   explicitly (D1), and the floor the other contexts mount is closed to the known write scopes
   (D5).

## Decisions (Themis side)

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

## Honest limits

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

## Realizes

EDR-SECURITY-01 D1/D4 (the scope vocabulary as the authorization contract, now enforced at the
resource AND closed at both ends), EDR-HARNESS-01 D4 (the carried gap, closed), CONVENTIONS R1 (the
refusal's detail reaches console + OTel through the one shared logger), CON-0016 (traceability —
the principal is already the recorded actor; now it is also the authorization subject).

## Revision 2 (2026-10-01) — Remediation cycle (documentation only)

The owner restated the outward-actions workflow as a LOOP and gave the decisions that shape it.
Grilled and recorded runtime-side as **D-N-8..D-N-12**
(`themis-ai-runtime/openspec/changes/outward-actions/design.md`); this revision records what they
require of THEMIS.

The cycle: an SBOM is uploaded under Product / Project / Release / SBOM id and Themis lists its
vulnerabilities → a Jira ticket tracks the fix → a Jenkins build produces a new image and a new
SBOM uploaded to the same Product / Project / Release under a new SBOM id → Themis compares new
against previous (closed vs still open) and updates the ticket → the result goes out by mail →
the loop repeats until the targeted vulnerabilities are closed or a configured maximum number of
rebuilds is reached, after which it stops and tells a person.

**Nothing in this revision is implemented.** It changes no code, no API, no schema and no
generated handler. RC-1..RC-8 are decisions of record for the milestones that follow N-M0; where
a mechanism is genuinely undecided (RC-1's transport) it is named as such and deferred to its own
EDR and API change.

### RC-1 — The trigger is "release posture evaluated", not document receipt

SBOM upload starts an ASYNCHRONOUS evaluation. The remediation cycle starts when that evaluation
completes for the Release — not when the document is received. Until then no Jira ticket is
written, no mail is sent and no rebuild intent is issued: a ticket written from a half-evaluated
SBOM lists a subset and reads as truth, and a rebuild triggered on receipt rebuilds against
nothing.

Themis MAY publish a Themis-owned pub/sub notification carrying that signal, to which the AI
Harness may subscribe. Outward actions remain Themis-owned either way — the notification tells the
harness that a posture is settled; it delegates nothing.

Deferred, deliberately: event name(s), delivery semantics (at-least-once assumed), transport
(webhook vs bus-backed fanout vs long-poll), subscriber authentication, and whether the seam
belongs to Communication or Governance. That is a trust-boundary change and needs its own EDR and
API change before implementation. Until it exists, the current Governance events (`finding_opened`
and the posture-evaluated path) remain the effective trigger in code.

### RC-2 — Jira: one ticket per Release, CVE ids for Critical and High only

One ticket per Release, not one per Finding. The body carries severity COUNTS for Critical, High,
Medium and Low, and lists the CVE ids for **Critical and High only**; Medium and Low are counts
with no CVE list. The ticket is updated in place across the cycle's attempts, idempotently, keyed
by delivery intent id and attempt index.

The unit a rebuild addresses is a Release, so the unit a tracking ticket addresses is a Release.
Listing every CVE id at every severity makes the ticket unreadable at estate scale. Jira stays a
projection: no Themis state follows from a Jira transition, and the authoritative relationship
lives in Themis (D-N-7).

### RC-3 — `ci_rebuild`: a new delivery kind, APPROVED

A fourth delivery kind joins `jira_issue`, `ci_build` and `email`: **`ci_rebuild`** (Communication,
policy-gated). It rebuilds a Release without a fresh human proposal acceptance — the cycle's
authority comes from the policy that started it, bounded by lineage and knobs.

- Snapshot: destination pipeline name, Product / Project / Release identity, prior SBOM id, the
  targeted Finding set, attempt index. **No credentials, no keys, no model output** — destinations
  stay governed names (D3 of this EDR's parent decisions, D-N-3 runtime-side).
- Callback: MUST carry the **new SBOM id** and the **image digest**, alongside
  `{intent_id, build_id, git_ref}`. It is recorded as governed-external evidence on the intent and
  changes no Finding state. A build system asserting a fix is refused; only the evaluation of the
  new SBOM can establish absence of a fault.
- Authorization is unchanged: the callback enters through the Communication boundary under
  `delivery:callback` (or the HMAC transport variant), which D1/D2 keep refused on every Governance
  write.

**`ci_build` is unchanged** and keeps its governance-controlled path: it carries an accepted change
artifact and follows `proposal_accepted`. `ci_rebuild` carries no artifact. The two must not be
conflated — one materializes a human-accepted change, the other repeats a build.

Approved means approved as a decision of record. It is NOT implemented, and its knobs are
documentation until the milestone that builds them.

### RC-4 — Comparison: new SBOM against previous, per Release

On each new SBOM produced by a rebuild and evaluated, Themis compares it against the previous SBOM
for the same Product / Project / Release to determine which targeted vulnerabilities are CLOSED and
which are STILL OPEN. That comparison is the cycle's only measure of progress, and the Jira ticket
(RC-2) is updated from it.

Open: whether the baseline is strictly the immediately-previous SBOM id for the Release or a
configured baseline window.

### RC-5 — Email after the comparison, never from the callback

A plain-text mail goes out on each attempt, AFTER the comparison of RC-4 — not on the build
callback, which only says a build happened. Recipients are governed Communication audiences
resolved by the mail worker; addresses and credentials are never carried in the intent. Content
derives from the immutable delivery snapshot: no model output, no workspace content, no key
material, no attachments. One mail per intent id; a retry is a delivery retry, not a new
communication event.

### RC-6 — Loop control: default max-attempts = 2 per Release

Success is the targeted set closed; the loop stops. Otherwise it repeats, bounded by a maximum
number of rebuild attempts per Release: **default 2**, operator-configurable (configuration locus
and name to be fixed by the implementing milestone; raising it later is expected once the loop has
a reliability record). Two is deliberately low — a loop that cannot fix a Release in two attempts
will not fix it in ten, and a high limit means a pipeline hammering itself while nobody reads the
mail.

On exhaustion the loop STOPS and tells a person: mail to the governed audience plus a Jira update
stating the attempts are exhausted. **Findings are never auto-resolved** — resolution is a decision
about exposure, not about the existence of a fix, and stays a human act (D-N-7). A failed attempt
is an outcome, not an error: it is recorded, the Finding stays as it is, and the original Release
stays affected.

### RC-7 — Ownership and the invariants a loop is most likely to erode

**Themis owns** security truth and every outward effect: SBOM intake and evaluation, posture and
Findings, the RC-4 comparison, delivery intents and workers, Jira, CI (`ci_build` and
`ci_rebuild`), mail, the attempt counter, the stop condition, and the RC-1 notification it
publishes. **The AI Harness owns** runtime execution and orchestration of its own work and MAY
subscribe to the RC-1 notification; it remains networkless for Jira, CI and mail, holds no outward
credential, and initiates no Governance act.

Invariants restated because a loop is where they slip: model output is advisory and never enters a
delivery payload; payloads derive only from the immutable snapshot; secrets never travel in an
intent; controls fail closed (no evaluation signal → no outward action); and external availability
never blocks or changes Themis truth — outward failure is dead-letter state, never a Finding
change.

### RC-8 — N-M0 is unchanged (see also M1a-9: N-M1a changes nothing here either)

Explicit per-route write-scope authorization stands exactly as implemented (D1–D7, Group 1,
2026-09-30): `delivery:callback` refused on every Governance write unconditionally, `admin`
allowed, `product:<id>` confined to the product that owns the Finding's release, everything else
refused, the scope vocabulary closed at both ends. `ci_rebuild`, the RC-1 notification and the loop
imply **no new scope, no relaxation and no new Governance write path**. Any reading of this
revision that weakens N-M0 is wrong.

## Revision 3 (2026-10-02) — N-M1a: delivery intents, IMPLEMENTED

Revision 2 recorded the loop. **N-M1a builds its first half, and only its first half**: Themis
now RECORDS what must go out and SENDS it in a worker, against fake senders. Scope was fixed by
owner feedback on the plan: deduplicate on the originating event id, and carry **no CI-build
content of any kind** in this step.

What landed (Communication context, greenfield tree): two tables, a store, an app service, two
mappings in the Governance-stream reader, a worker with retry/backoff/dead-letter, fake Jira and
mail senders, and an operator CLI. No API change, no OpenAPI edit, no generated handler, no
network call.

### M1a-1 — The event reader PERSISTS; it never delivers

The inbound consumer's whole outward job is to write a `delivery_intents` row inside the inbox
unit of work. It holds no Jira client, no mail client and no HTTP client at all, so an
unreachable external system cannot block, slow or stall the bus reader path. Sending is a
separate worker on its own cadence.

This is the structural form of RC-7's "external availability never blocks or changes Themis
truth". Stating it as a rule is not enough — a reader that *could* call out would eventually be
made to, so the reader is wired without the means.

### M1a-2 — Idempotence is keyed on the ORIGINATING EVENT ID

`delivery_intents.origin_event_id` is the kernel envelope id, under a partial unique index
(`WHERE origin_event_id IS NOT NULL`). `CreateIntent` inserts `ON CONFLICT DO NOTHING` and
returns the row that is already there. The bus is at-least-once, so a replay is the normal case:
it yields one ticket and one mail, never two.

The owner chose this over the partial uniqueness per `(release_id, type)` that the first plan
carried, and the consequence is recorded rather than papered over: the mapping is now strictly
**one event → one intent**. Combined with the proxy trigger in M1a-3, a Release with twelve
opened Findings currently asks for twelve ticket intents — so **RC-2's "one ticket per Release"
is NOT yet realized**. It cannot be, honestly, until the trigger is a per-Release signal; keying
dedup on a per-Release guess would have produced one ticket whose contents depended on which
Finding happened to arrive first.

Worker-sourced intents (the dead-letter notification) store NULL and take part in no
uniqueness — there is no event to dedupe them against.

### M1a-3 — The trigger is a recorded TEMPORARY PROXY

RC-1 / D-N-8 names "release posture evaluated" as the trigger. No such signal exists, so N-M1a
proxies it with **`governance.finding_opened`** and records the deviation here, in the code
comment at the mapping, and in the change's tasks. `governance.proposal_accepted` maps to the
decision mail and is not a proxy — an accepted proposal is exactly the fact being notified.

Product and project are left EMPTY on a ticket intent: the `finding_opened` contract does not
carry them, and resolving them would mean a Registry read on the reader path, which M1a-1
forbids. An intent that names no Release records **nothing at all** — an outward action with an
indeterminate subject is precisely the one that must not go out (fail closed).

### M1a-4 — Giving up is a state, and it tells a person with another INTENT

An attempt that fails is recorded (append-only `delivery_attempts`), backed off
(`initial × 2^(n-1)`, capped), and retried. After `MAX_ATTEMPTS` the intent moves to
`dead_letter` — terminal until a person acts — and the worker **enqueues an email intent** to
the governed dead-letter audience. It does not send one inline: the failure path must not depend
on the channel that just failed.

The chain stops at one. A dead-letter notification that itself dead-letters does NOT produce
another notification — it is logged at error instead. Otherwise one unreachable relay fills the
table with notifications about notifications, and the alert that matters (the telling-a-person
channel is broken) is buried in them.

A failed delivery is an **outcome, not an error**: nothing about a Finding, a Position or a
posture changes. The worker reports an error only when the STORE fails — the one failure that
means the record of what happened is itself unreliable.

### M1a-5 — FAKE senders, deliberately

Both deliverers log and return an outcome; neither opens a socket. The mechanics N-M1a has to
get right — claim order, attempt ledger, backoff, exhaustion, the notification, the operator
reset — are all provable without a Jira instance, and a half-real sender would have made the
step's test suite depend on a credential. The real senders arrive in N-M1b behind the same
`IntentDeliverer` seam. `payload_sha256` / `payload_bytes` stay empty for the same reason:
materialization belongs with the sender that fixes the body's shape.

### M1a-6 — The operator surface is a CLI, not an API

`cmd/deliveryctl` (`list-deadletters` · `retry` · `cancel`), reading the Communication database
like `cmd/authadmin` reads the auth one. N-M1a adds **no HTTP surface**. An id that names
nothing actionable — unknown, or already delivered — exits non-zero: an operator who typed the
wrong id has to be told. `retry` clears the counters but never the attempt ledger: the counter
answers "may we try again", the ledger answers "what happened", and a retry must not erase the
second. Neither command touches a Finding or a Position.

### M1a-7 — One switch over BOTH halves

`THEMIS_COMMUNICATION_DELIVERY_ENABLED` (default **off**) gates the worker **and** the reader's
intent recording. Off means off: no intents are written and nothing is sent. Gating only the
worker would have let a default-configured node silently accumulate a queue nobody drains, which
is indistinguishable from an outage to the person who later turns delivery on.

### M1a-8 — The intent carries facts, never credentials or model output

`snapshot` holds the identity facts of record (stamped by the app service, so a caller cannot
omit them), `lineage` the originating envelope's identity, and `destination` a **governed name**
— an audience, a project alias — resolved to real addresses by the sender. No address, no key,
no model output, no workspace content. Telemetry carries the intent id, the destination, the
origin event id and the correlation id, and never the payload: a delivery body is outward
content, and a log is not an outward channel.

### M1a-9 — NO CI-build content in this step

There is no `ci_build` and no `ci_rebuild` intent type, no CI worker, no callback route and no
rebuild loop. The intent-type vocabulary is CLOSED to `jira_issue` and `email`, enforced by a
CHECK constraint, so a CI kind cannot appear by accident. RC-3's `ci_rebuild` and the `ci_build`
path remain decisions of record with **no realization**; the rebuild loop (RC-4/RC-6) is
untouched. N-M0 is likewise unchanged (RC-8): no new scope, no relaxation, no Governance write.

### Honest limits (N-M1a)

- **RC-2's ticket content and one-per-Release rule are not implemented** — see M1a-2/M1a-3. What
  exists is the intent, not the ticket body.
- **Two Communication NODES draining the same database can both claim the same intent.** The
  claim is a plain due-time read, in-process concurrency is safe (one fetcher, N senders), and
  the `IntentDeliverer` contract requires idempotence per intent id — which makes this a
  duplicate-suppression question for the real senders in N-M1b, not a correctness hole now.
- **State transitions are owned by `MarkDelivered` / `MarkDeadLetter` / `CancelIntent` /
  `RetryIntent`, not by `RecordAttempt`** (one writer per transition). A crash between the last
  failed attempt and the dead-letter write is self-healing: a worker that fetches a pending
  intent whose attempts already reached the maximum finishes it WITHOUT sending again.
- **`lineage` carries no `event_seq`.** The bus sequence is the `event_log`'s own ordering column
  and is not carried in the kernel Envelope (EB-02); recording it would mean inventing a number.
- The foreign ids (product/project/release/finding/proposal) are **TEXT, not UUID**: they are
  other contexts' identities, carried verbatim and never parsed, so no format is imposed on
  Registry or Governance — the same rule D5 applies to `product:<id>`. The intent's own id is a
  UUID, because Communication mints it.
- The dead-letter notification has **no deduplication key** (it is worker-sourced). Nothing
  deduplicates it but the fact that an intent dead-letters once.

### Realizes

`internal/communication/adapters/store/migrations/000006_delivery_intents.{up,down}.sql` ·
`adapters/store/delivery.go` · `app/delivery_intent.go` · `adapters/inbound/consumer.go` ·
`adapters/delivery/{delivery,worker}.go` · `adapters/wiring/wiring.go` (`WireDelivery`) ·
`cmd/communication` · `cmd/deliveryctl` · `deploy/node.env.example`. Conventions: R1 (console +
OTel from the one shared logger, secrets and payloads redacted), R2 (self-documented config).
