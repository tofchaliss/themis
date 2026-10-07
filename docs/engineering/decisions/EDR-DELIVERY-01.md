# EDR-DELIVERY-01 — Outward actions: explicit write-scope authorization (N-M0)

Status: **Accepted 2026-09-30** for N-M0; **Revision 2 (2026-10-01) — remediation cycle, accepted
as a decision of record, NOT implemented**; **Revision 3 (2026-10-02) — N-M1a delivery intents,
IMPLEMENTED** (intents are persisted and sent by workers against FAKE senders); **Revision 4
(2026-10-02, amended 2026-10-05, -06 and -07) — N-M1b real Jira + mail senders and payload
materialization, IMPLEMENTED** (both channels OFF by default, secrets from the environment only, one
ticket per Release; the CI build and the rebuild loop are still later milestones). Three amendments
came out of the enterprise-VM run: **M1b-8** (2026-10-05) — Communication's Governance and Registry
READS carry `X-API-Key` from `THEMIS_API_KEY`; **M1b-3a** (2026-10-06) — the estate's Jira is
self-hosted **Data Center**, so auth mode (`basic`/`bearer`) and REST version (`3`/`2`) are
configurable, defaulting to Cloud; **M1b-4a/4b** (2026-10-07) — the estate's project forbids labels on
create, so Themis's OWN RECORD became the ticket index and labels a best-effort follow-up edit, and the
project's issue-type id + required custom fields are configurable. The decisions were grilled and
locked with the user in
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

## Revision 4 (2026-10-02) — N-M1b: the real Jira and mail senders, IMPLEMENTED

N-M1a proved the mechanics against fakes. **N-M1b makes two of the three channels real** — Jira
and mail — behind the same `IntentDeliverer` seam, and materializes the payload at enqueue so a
retry re-sends bytes instead of re-deriving them. RC-2's ticket content lands with the Jira
sender. **The CI build and the rebuild loop are still not in this step** (M1b-7).

### M1b-1 — Both real senders are OFF by default, and independently

`THEMIS_COMMUNICATION_JIRA_ENABLED` and `THEMIS_COMMUNICATION_MAIL_ENABLED` are two switches, both
default off, both subordinate to `THEMIS_COMMUNICATION_DELIVERY_ENABLED`. With the mechanism on
and both channels off, the fakes stay wired — which keeps M1a-7's property exactly: "delivery is
running" never implies "something left the estate". A mixed state is supported and expected: the
two channels are credentialed separately, so they are enabled separately.

An **enabled but incompletely configured** channel keeps the FAKE sender and logs at ERROR naming
the environment variables that are unset. Both halves of that are deliberate. The queue must keep
draining — an undrained queue hides every other outward obligation behind the first
misconfiguration — but "I am sending to Jira" and "I am logging instead" must never be
indistinguishable in a log, which is why the fallback is loud and names the knob.

### M1b-2 — Secrets come from the environment, and from nowhere else

The Jira API token and the SMTP password are read from the environment only. No configuration file
in this repository holds one and none may (R2); `deploy/node.env.example` documents them as
commented, valueless knobs. `Config.String()` — the startup line an operator reads — prints
`api_token=set` / `password=unset`, never a value, and no error, excerpt or log field built by
either sender carries a credential. The mail configuration's `String()` additionally prints only
the audience NAMES: a recipient list is estate detail.

Two guards are stronger than configuration, and they are the SAME rule applied to both channels: **a
credential never crosses an unencrypted channel.**

- Jira: a `http://` base URL is **refused**, because the credential is HTTP Basic — the token is in
  every request, and base64 is an encoding, not protection. A scheme that is neither http nor https
  is refused outright rather than left for `net/http` to fail on later.
- Mail: a username **without** STARTTLS is **refused**, because the password would cross the network
  in the clear. `net/smtp` enforces the same rule one layer down, so such a node could never have
  sent anyway.

Both make exactly one exception, for exactly one reason: a **loopback** host, whose bytes never leave
the machine. That is also where an `httptest` server and a local relay live, so a development
deployment needs no knob — and a knob is precisely what must not exist, because a knob that relaxes
this in development is a knob that can be set in production.

Both refusals happen at CONFIGURE time, not at send time. A misconfiguration that exposes a
credential must not be discovered by having exposed it once per retry; and because the selection
(M1b-1) then keeps the fake sender, the node keeps draining its queue and says at ERROR why nothing
is reaching Jira.

### M1b-3 — The payload is materialized at ENQUEUE, and a sender never renders (D-N-3)

`payload_bytes` + `payload_sha256` are filled when the intent is created, by an app-level
`IntentPayloadRenderer` the outward serializer implements. Every retry transmits those exact
bytes. A sender handed an intent with no payload REFUSES it (`ErrNoPayload`) rather than rendering
one from current facts: render-at-send would make "the same snapshot was delivered" unverifiable,
and a body nobody recorded is a body nobody can audit.

A render that fails enqueues **nothing** — the originating event is retried by the bus, so the
obligation is not lost. This is the same fail-closed shape as `ErrNoSubject`: an intent whose
content could not be determined is exactly the intent that must not sit in a queue waiting for
somebody to decide what it says. On a replay the render runs again and is discarded, because
`CreateIntent` returns the row already stored — determinism is a property of the RECORD, not of
the renderer.

Consequence, recorded because it is operator-visible: intents written by N-M1a carry no payload,
and a real sender dead-letters them instead of inventing a body.

### M1b-3a — TWO Jira flavours, two knobs, one sender (owner decision, 2026-10-06)

**Measured on the enterprise VM.** The estate's Jira is **self-hosted Data Center** at
`https://almsbx.radisys.com/jira`, not Cloud. The first cut assumed Cloud throughout and was wrong in
three ways at once: it sent the credential as HTTP Basic (Data Center issues a **Personal Access
Token** for `Authorization: Bearer`), it addressed `/rest/api/3` (Data Center serves **v2**), and v3's
description is an **Atlassian Document Format** object where v2 wants a **plain string**.

Owner decision: two knobs, **defaulting to Cloud** so an existing deployment sets neither.

| | `THEMIS_COMMUNICATION_JIRA_AUTH` | `THEMIS_COMMUNICATION_JIRA_API_VERSION` |
| --- | --- | --- |
| Cloud (default) | `basic` — account email + API token | `3` — description as ADF |
| Data Center / Server | `bearer` — PAT, no user at all | `2` — description as plain text |

Three things about the shape, each chosen rather than fallen into:

- **The version knob selects the path prefix AND the description encoding**, because they are not
  independent. Splitting them would let an operator configure a combination that cannot work, and the
  failure (a 400 on every attempt) would read as "Jira rejects our tickets" rather than as a
  configuration error.
- **Neither vocabulary falls back.** An unrecognized value is refused at startup with the variable
  named and both options spelled out. A fallback to `basic` sends a PAT as a password — a 401 that
  reads as "the token is wrong" — and a fallback to `3` sends ADF to v2. Both make a typo look like
  someone else's fault.
- **The USER is required only under `basic`.** A PAT identifies its own owner; demanding an account
  email under `bearer` would make an operator invent a value for a field the request does not carry.

**The base URL may carry a PATH**, which is how a self-hosted instance is normally mounted. Every
endpoint is built by APPENDING to the configured URL — never by replacing its path — so `/jira` is
preserved and no second code path exists for it. A bare `host/path` with no scheme is refused, since
that is the likeliest paste and it would otherwise become a relative request.

**Everything else is shared, and that is the claim worth making.** The JQL label search, the
labels, the summary, the full-replace update, the content rule — all identical, because
one-ticket-per-Release must not be a property that holds on one flavour. Both flavours run the same
behavioural tests: create, update, path addressing and the whole posture-to-ticket path.

### M1b-4 — One ticket per Release is a LABEL, not a summary search (RC-2)

The Jira sender looks for the Release's existing issue by the exact label
`themis-release-<release-uuid>` (JQL `labels = "…"`), and replaces its summary and description
from the snapshot; it creates the issue only when the label matches nothing. The created key is
recorded on the intent's delivery result (`jira_issue_key`).

A label rather than `summary ~ "<uuid>"` because a text search depends on how Jira tokenizes a
hyphenated id, and a near-miss there does not fail — it silently opens a second ticket for a
Release that already had one. This answers the open question Revision 2 left ("is JQL search
acceptable for idempotent update, or should we set a field/label?"): a label, searched exactly.

The update is a **full replace**, which is what makes it idempotent by construction: applying it
twice leaves the issue in the same state, so a retry after a timeout whose PUT actually landed
costs nothing. Jira stays a projection — no Themis state follows from a Jira transition (D-N-7).

### M1b-4a — A project may forbid labels on create, so THEMIS'S OWN RECORD is the index (owner decision, 2026-10-07)

**Measured on the enterprise VM, project ME.** Labels are not on that project's create screen, so Jira
answered `Field 'labels' cannot be set` — and refused **the whole create** over that one field. Every
ticket failed. Worse, the fix is not just "move the labels": if labels can fail to apply, then a label
search can fail to FIND, and the one-ticket rule was resting entirely on it.

The ordering changed, and this is the substance of the decision:

1. **Themis's own record** — the `jira_issue_key` on an earlier *delivered* intent for that Release.
2. **The label search** — now the FALLBACK, for a Release Themis has no record of.
3. Create.

Themis's record depends on nothing external: not on the search index having caught up, not on the
credential being allowed to browse, not on a label having been applied. Asking Jira what Jira knows
about work Themis did was always the weaker question; the ME project just made the weakness fatal.

The create carries **no labels**, and they are added by a follow-up `update`-style edit that is
**best effort**: on failure the ticket stands, the key is recorded, and the next update retries —
`add` is idempotent, so every later cycle retries for free with no state to track. A failed label edit
must never fail the delivery, because a failed delivery retries the whole thing *including the create*,
on an intent whose key the store has not yet recorded. That is precisely the path that opens a second
ticket, and a second ticket costs more than a missing label.

Work on one Release is **serialized in-process** (a per-Release lock held across lookup AND create).
Checking first and creating later with no lock between is the race, not a fix for it — and the
`finding_opened` proxy produces intents for one Release by the dozen, all due at once, drained by
`cfg.Workers` goroutines. A process-local memo of the key sits beside the lock because the durable
record arrives too late to help: the key reaches the store when the WORKER marks the intent delivered,
which is after the sender has returned.

The delivery result now records **how** the ticket was found (`jira_found_by`: `memo`,
`themis_record`, `label_search`, `created`) and **whether the labels landed** (`jira_labels`:
`added` / `pending`), so an operator can see which mechanism is carrying the rule rather than
inferring it.

### M1b-4b — Issue type by ID, and the project's own required fields (owner decision, 2026-10-07)

The same project needs `issuetype` **by id** (10501) and four required custom fields plus a version
before it will accept a create at all. Two knobs, both unset by default:

- `THEMIS_COMMUNICATION_JIRA_ISSUE_TYPE_ID` — when set, the issue type is sent by id and the **name is
  not sent at all**. Sending both would let Jira decide which it believes. An id is also the only way
  to address a project whose type names are renamed, localized or duplicated across schemes.
- `THEMIS_COMMUNICATION_JIRA_EXTRA_FIELDS` — a JSON object merged into every **create**'s `fields`,
  passed through verbatim so the field's own shape stays the operator's choice.

Three constraints on the merge, each load-bearing:

- **It can never override `project`, `issuetype`, `summary`, `description` or `labels`.** Those are the
  ticket's identity and its snapshotted content; a configuration file silently replacing the body of a
  security ticket is the one thing this seam must not permit. A reserved key is dropped and the node
  logs which, so an operator who tried is told rather than left wondering.
- **Invalid JSON refuses the sender at startup**, and the fake stays wired. These fields exist because
  a screen *requires* them, so a typo must not be discovered one failed create per Release, forever.
- **Create only.** Re-asserting a priority or a version on every cycle would overwrite whatever a
  human changed on the ticket — the opposite of what a projection should do.

Also fixed with them: the issue type **name defaulted in only one half of the node**. The sender
applied `Task` internally while `ConfigFromEnv` left the field empty, so the startup line read
`issue_type=""` and disagreed with the request it was describing — and an operator debugging the
create failure above spent that disagreement looking for a gap that was not there. The effective
value is now resolved where it is read, like the auth mode and the API version beside it. A default
that only one half of a node knows about is a default that lies.

### M1b-5 — The ticket's four severity buckets are read off `base_score`

RC-2 asks for counts for Critical/High/Medium/Low and CVE ids for Critical and High only. The
Governance release-posture projection carries no severity WORD: it carries `base_score`
(Knowledge's CVE-intrinsic composite, 0–100) and `band` (which is EXPLOITABILITY, a different
question). The buckets therefore invert the same ladder Knowledge built the score from —
Critical ≥ 90, High ≥ 70, Medium ≥ 40, Low > 0 — read over the existing read seam, with no API
change and no second call per Finding.

Two consequences are stated rather than hidden. A card lifted by EPSS or KEV can cross into the
bucket above its intrinsic severity, which is the right answer for a ticket about what to fix
first and the wrong one if the ticket is read as a CVSS report. And a score of **0 is `Unknown`,
never `Low`** — it is counted and labelled separately, and only when non-empty, because the
absence of severity evidence is not evidence of mildness.

### M1b-6 — Mail: the audience name becomes recipients HERE, or nowhere

An intent carries a governed audience NAME; the mail sender is the one place it becomes addresses,
from an environment-supplied map. An audience with no mapping is **refused** rather than
redirected to a default: the wrong people reading a security decision is a worse outcome than a
dead letter an operator can see. The message is plain text, with no attachment, and its `Date`
comes from the intent's creation time and its `Message-ID` from the intent id — both immutable, so
a retry is byte-identical and a receiving relay can collapse the duplicate a timed-out send may
already have delivered (RC-5: one mail per intent id; a retry is a delivery retry, not a second
communication).

Governed audiences are still this map. A central audience registry does not exist yet; the map is
documented as the registry until one does.

### M1b-6a — Every outward step is BOUNDED, and every header value is FOLDED

Two hardening rules that are easy to leave out and expensive to add back once a queue is live.

**Bounded.** The Jira client carries a per-call timeout; the SMTP conversation bounds *every step*,
not just the dial. The difference is the failure that actually happens: a relay that accepts the
connection and then stops answering is not unreachable, so a dial timeout never fires, and a worker
goroutine blocks in a read forever — `cfg.Workers` such relays and the queue stops draining
altogether. A per-operation deadline (rather than one for the whole session) is what lets a slow but
*progressing* transfer finish while a step that is genuinely not moving fails. The worker's context
also closes the connection, so shutdown is not held up by a relay that is still thinking. The
Governance read seam is bounded for the same reason, and more sharply since N-M1b: it now runs inside
the inbox unit of work, where an unbounded read holds a bus-reader transaction open.

**Folded.** A CR or LF in a value destined for a message header does not produce a malformed header —
it produces ADDITIONAL headers, or an early end of the header block that turns the rest into body.
Every header value is folded at the boundary where the harm would occur, so no caller has to
remember; the subject is the one that can carry a newline today, because `SplitPayload` returns
whatever the stored payload holds and an N-M1a row was never promised to have folded it. An
ADDRESS, by contrast, is **refused** (a `From`) or **dropped** (a recipient, which leaves its audience
unmapped and therefore loudly refused): an address nobody can read as an address is a configuration
mistake, and a silently repaired one sends security mail somewhere the operator never chose.

### M1b-7 — Still NO CI build and NO rebuild loop

Unchanged from M1a-9, restated because this is the step where it would be easy to slip: there is
no `ci_build` or `ci_rebuild` intent type (the CHECK constraint still closes the vocabulary to
`jira_issue` and `email`), no callback route, no loop control and no attempt budget per Release.
RC-3/RC-4/RC-6 remain decisions of record with no realization. N-M0 is unchanged (RC-8): no new
scope, no relaxation, no Governance write, no API or OpenAPI edit in this step either.

### M1b-8 — Communication's READ seams carry `X-API-Key` from `THEMIS_API_KEY` (owner decision, 2026-10-05)

**Measured on the enterprise VM.** Governance and Registry ran with `THEMIS_AUTH_REQUIRED=1`.
Communication read the release posture with no credential, Governance answered **401**, the ticket
payload could not be rendered, so — correctly, by M1b-3 — **no intent was recorded** and the
`finding_opened` envelope retried. Forever. The pipeline stopped at the first Finding of the first
Release, behind an error that read like a broken endpoint.

Owner decision: **Communication's Governance and Registry read clients send `X-API-Key` from
`THEMIS_API_KEY` when it is set; unset means no key, as before.** One variable, the same name the
Dashboard proxy and the Intelligence node already use — an operator who has provisioned one node has
provisioned this one. A **read-scoped** key is enough and is what the documentation tells an operator
to mint: this node writes to neither context, so a key that cannot write is a key that cannot be
misused if it leaks.

This closes, for Communication only, the limit N-M0 recorded ("the read seam sends no API key"). It
is the milestone that needed it. The equivalent on **Governance's** Registry client — where the
consequence is that a `product:<id>` key cannot resolve its product — is still open (task 2.10) and
is a separate decision, because its failure mode is a refused write rather than a stalled reader.

Two details that are not incidental:

- **Trimmed.** A key pasted into an env file arrives with whitespace the operator cannot see, and
  `X-API-Key: <key>\n` is not the key. Both clients trim.
- **The error names the variable.** A 401/403 now says whether the read sent *no* key (set
  `THEMIS_API_KEY`) or one the node *refused* (check it is current and read-scoped) — two different
  places to look, and the distinction is the whole value of the message. The key itself never appears
  in an error, and startup logs only whether one is set.

### Honest limits (N-M1b)

- **Two Communication NODES can still open two tickets for one Release.** The per-Release lock is
  in-process, and Themis's record only answers once the first node's intent is marked delivered — so a
  genuine simultaneous first delivery on two nodes is not covered. M1b-4a narrows this a long way (the
  record answers from the second delivery onward, whatever Jira's index or labels do) without closing
  it; closing it needs a store-level claim, which is its own step.
- **A create that succeeds but whose outcome is never recorded can be repeated.** If the process dies
  between Jira accepting the create and the worker marking the intent delivered, the key is lost from
  Themis's record; the label search is then the only backstop, and on a project that forbids labels on
  create there may be no label to find. The window is one write wide and the consequence is a second
  ticket, not lost work — but it is real, and Jira offers no idempotency key to close it.
- **Search permission still matters, but only for the fallback.** A credential that may create and
  edit but not browse now works for every Release Themis has a record of.
- **Two Jira flavours are supported, and a THIRD would be a third decision** (M1b-3a): Cloud
  (`basic` + v3) and Data Center / Server (`bearer` + v2). OAuth, a reverse proxy that rewrites the
  REST path, and Jira's own newer `/search/jql` endpoint are all out of scope here. An instance that
  differs yields dead letters, not a halted stream (D-N-2 / RC-7).
- **The TLS handshake of STARTTLS is not covered by a test** (it needs a trusted certificate). The
  "configured but not offered" refusal is.
- **Rendering a ticket reads Governance on the enqueue path.** The reader still holds no Jira, mail
  or SMTP client (M1a-1 stands), but materialization means ONE read-API call per ticket intent
  inside the inbox unit of work, and a failed read means no intent rather than a half-determined
  one. That is a deliberate trade of reader latency for the snapshot guarantee; the alternative
  put rendering back in the sender. **This is what made M1b-8 urgent rather than tidy**: the same
  read on a request path would have degraded one response, and on the reader path it stalls a
  stream.
- **A read-API 401 is still a RETRY LOOP, not a dead letter.** M1b-8 gives the seam a credential; it
  does not change what happens when the credential is wrong. The envelope retries on the bus's own
  schedule with no attempt ceiling, because an inbound event is not a delivery intent and has no
  attempt counter. The error now names the variable, which is what makes the loop diagnosable in one
  log line — but an operator who ignores it has a stalled stream, not a dead-letter queue.
- **The ticket counts every Finding of the Release**, including those a Position has already
  suppressed. Filtering by disposition is a policy decision nobody has taken, and inventing one
  here would quietly change what the ticket means.

### Realizes

`internal/communication/app/delivery_intent.go` (payload envelope, `IntentPayloadRenderer`,
`ReleaseSeverityReader`, materialization) · `adapters/serializer/outward.go` ·
`adapters/governance/client.go` (`ReleaseSeverity`, `WithAPIKey`) ·
`adapters/registry/client.go` (`WithAPIKey`) · `adapters/delivery/{delivery,jira,mail}.go` ·
`adapters/wiring/wiring.go` (`Wire` now takes the read-API key) · `cmd/communication` ·
`deploy/node.env.example` · `deploy/systemd/install-systemd.sh`. No migration (the columns exist
since N-M1a), no API change, no new package, no new dependency.

## Revision 3 — N-M2 (2026-10-07)

The release-evaluated trigger, the polling subscriber seam, `ci_rebuild` over Jenkins, and the
loop. **Accepted as a decision of record. DOCUMENTATION ONLY — NOT implemented.**

**Numbering note.** This is the outward-actions PLAN's **Revision 3 — N-M2** (N-M0 authorization →
the remediation cycle → N-M2), and it is this FILE's fifth revision section: the sections above are
numbered 2, 3 and 4, because N-M1a and N-M1b each took one as they landed. The heading carries the
plan's name because that is the name this decision was given. Nothing above this line is amended —
not the status line, not a prior section's prose: **this record is append-only**, and where a later
section disagrees with an earlier one it says so here, in the later section.

**Documentation only. Nothing here is implemented.** No Go code, no OpenAPI edit, no generated
handler, no migration and no new dependency lands with it; `make check` is run to prove exactly
that. M2-1..M2-9 are decisions of record and N-M2a..N-M2j are the steps that will realize them.
This revision CLOSES every question Revision 2 left open (RC-1's transport and owning context,
RC-4's baseline window, RC-6's knob name and locus).

### What this revision supersedes (read M1a-3 with this)

**M1a-3's temporary `finding_opened` proxy is superseded by M2-1..M2-3, and will be removed from
the code by N-M2c.** M1a-3 recorded the deviation honestly and named what it cost: RC-1's
"release posture evaluated" signal did not exist, so N-M1a proxied it with
`governance.finding_opened`, which carries neither product nor project and fires once per Finding
rather than once per Release. Both consequences stop being consequences here —
`governance.release_evaluated.v1` is a per-Release signal that carries the product and the project,
so a ticket intent names its product and one Release evaluation yields one intent. That is also
what finally realizes RC-2's one-ticket-per-Release rule, which M1a-2 recorded as not yet
realizable.

Nothing else in M1a-3 changes: `governance.proposal_accepted` → the decision mail was never a proxy
and is untouched, and M1a-1's rule (the reader persists, it never delivers) still forbids resolving
identity on the reader path — the new event is the reason that resolution is no longer needed.

### M2-1 — The trigger is a release-evaluated EVENT, and the ordering is a bus property, not a race

Two events, in one direction:

1. **Knowledge** publishes `knowledge.release_correlation_completed.v1` **once per SBOM**, strictly
   AFTER every other Knowledge event it raises for that SBOM.
2. **Governance** consumes it and publishes `governance.release_evaluated.v1` — the signal RC-1
   asked for, now with a name.

The ordering guarantee comes from the transport, not from a wait. The bus delivers rows in `seq`
order per `source_context` (EDR-EVENTBUS-01), so by the time Governance handles the
correlation-complete event, every earlier Knowledge event for that SBOM has already been handled.
That is the whole reason the signal is an event appended LAST rather than a timer, a debounce or a
"quiet for N seconds" heuristic: a heuristic answers "probably finished", and a ticket written from
a probably-finished posture lists a subset and reads as truth (RC-1).

**The owning context is Governance, and that was a choice.** Knowledge knows when correlation
finished; it does not know what the posture IS — counts are Governance's Findings, over Governance's
own projection. A signal published by the context that cannot state the fact would force every
subscriber to go and ask, which is the asking the signal exists to avoid. Knowledge therefore says
"I am done with this SBOM" and Governance says "here is what it means".

### M2-2 — `governance.release_evaluated.v1`: the payload, and why zero counts are the SUCCESS case

Field names are **snake_case** and counts are **integers** — the kernel envelope's body convention,
and the one shape a JSON consumer never has to guess at:

```json
{
  "product_id":  "<id>",
  "project_id":  "<id>",
  "release_id":  "<id>",
  "sbom_id":     "<id>",
  "severity_counts": { "critical": 0, "high": 0, "medium": 0, "low": 0 },
  "cause": "new_sbom"
}
```

`cause` is a closed two-value enum: **`new_sbom`** · **`rediscovery`** (M2-3). The four ids are
carried verbatim as TEXT, never parsed — the same rule the delivery intent's foreign ids follow
(N-M1a honest limits) and the same rule `product:<id>` follows (D5).

**An SBOM with no matched vulnerabilities still emits BOTH events, with all four counts zero, and
that is a success — not a skip.** Suppressing the event when there is nothing to report is the
single most tempting shortcut here and it is wrong twice over: a subscriber cannot distinguish
"evaluated, clean" from "not evaluated yet" or from "the pipeline is broken", and the rebuild loop's
stop condition (M2-8) is literally "the targeted set is empty" — which an SBOM that reports nothing
can never demonstrate. Silence must mean exactly one thing, and here it means a fault.

The counts use the four-bucket ladder M1b-5 already established over `base_score`
(Critical ≥ 90, High ≥ 70, Medium ≥ 40, Low > 0), so the event and the Jira body cannot disagree
about what "High" means. A `base_score` of 0 is `Unknown` and is NOT counted as `low` — the absence
of severity evidence is not evidence of mildness. `severity_counts` therefore need not sum to the
Release's Finding count, and a consumer must not assume it does.

### M2-3 — Re-discovery sets a cause, and never starts or advances the loop

The re-discovery sweep (KN-RECOR-1) re-runs correlation for the stalest correlated Releases, so a
CVE published after a Release's last upload still reaches its inventory. It emits the same two
events with **`cause: "rediscovery"`**, and the loop ignores them: a rediscovery **never starts a
cycle and never advances an attempt counter**.

The reason is that a rediscovery is not a rebuild. Nothing was built, no new SBOM exists, and the
comparison of M2-5 has no new side. A sweep that advanced the loop would burn a Release's two
attempts (M2-8) on a feed update nobody asked for, and the operator would see "attempts exhausted"
on a Release that was never rebuilt once. Carrying the cause IN the event rather than letting the
consumer infer it from "did the SBOM id change" is deliberate: the producer knows why it is
publishing, the consumer would be guessing, and a wrong guess silently spends a budget.

What a rediscovery MAY do is everything that is not the loop — it is a real posture change and
subscribers that only report are entitled to it. The rule is scoped to the cycle: no `ci_rebuild`
intent, no attempt increment, no exhaustion notice.

### M2-4 — The harness subscribes by POLLING a Governance cursor read API

RC-1 deferred the transport. It is decided now, and it is the smallest thing that works:

```
GET /api/v1/governance/events/release-evaluated?after=<sequence>&limit=<n>
X-API-Key: <read-scoped key>
```

- **Cursor = the event SEQUENCE number, not the event id.** A cursor has to be ORDERED — `after`
  means "everything later than this" — and an id is a name, not a position. Paging on an id forces
  the server to look the id up to find out where it is, and answers nothing at all when the id is
  one the server has never seen.
- **`limit` defaults to 100 and is capped at 500.** A default exists so a client that omits it
  cannot ask for the table; a cap exists so a client that asks for a million cannot be given one.
  A value above the cap is clamped, not refused — a paging hint is not a correctness claim.
- **Authentication is `X-API-Key` with READ scope.** The subscriber only reads. A read-scoped key
  cannot write anywhere in the estate (D5), so this credential leaking costs visibility, never
  integrity — and the harness holding a write-capable key to learn that an evaluation finished would
  invert D-N-1 (the harness initiates no Governance act).
- **At-least-once, deduplicated by EVENT ID.** The same row may be delivered twice (a client that
  crashes before storing its high-water mark re-reads the page); the consumer discards an event id
  it has already seen. The sequence orders, the id identifies — each does one job.
- **No SSE, no webhook, no long-lived connection.** A webhook would make Themis call OUT to the
  harness, which hands the harness an inbound surface and Themis an outbound credential for it —
  the exact trade N-M0 exists to avoid. SSE adds a connection whose liveness becomes an operational
  question ("is the stream up?") separate from the data's. A poll has one failure mode: the next
  poll. It also makes the subscriber's progress its OWN state, which is why a down harness costs
  nothing but lag.
- **The events are stored server-side**, in a new Governance table **`release_evaluated_events`**
  (N-M2d), because a cursor API cannot be served from a bus that has already delivered the message.
  The table is the audit trail too: "what did Themis say about this Release, and when".
- **No retention or purge policy is set.** The rows are small, one per evaluated SBOM, and a purge
  policy that silently moves a cursor past deleted rows is worse than growth an operator can
  measure. It is a deliberate non-decision, not an oversight.

**The harness only SUBSCRIBES.** It calls no Jira, no CI and no mail relay, holds no outward
credential, and takes no Governance act (RC-7 / D-N-12). Reading this endpoint is not authority.

### M2-5 — The baseline is the immediately-previous SBOM, and the targeted set does not GROW

RC-4 left the baseline open. It is now fixed: the comparison is **the new SBOM against the
immediately-previous SBOM of the SAME Release, by upload order**. No configured window, no
"baseline of record", no operator knob. Progress is "did THIS rebuild close anything", and a
configurable window answers a different question — one nobody has asked and whose answer changes
when the knob changes.

The **targeted set** is the Critical and High Findings present **at cycle start**, and it **does
NOT grow during the loop**. A Critical that appears mid-cycle (a new feed enrichment, a new CVE)
shows up in the ticket's counts — the ticket always states the Release's current posture — but it
does not join the set the loop is trying to close, and it waits for the next cycle.

Both halves of that matter. A growing target can never be reached, so the loop would always exhaust
its attempts and always report failure, however well the rebuild worked; and the attempt budget of
two (M2-8) would be spent on work the cycle did not set out to do. Counting it in the ticket while
excluding it from the target keeps the human's view complete and the machine's goal fixed.

### M2-6 — `ci_rebuild` over Jenkins: `buildWithParameters`, HTTPS or refuse at startup

RC-3's fourth delivery kind gets a sender. It starts a Jenkins job with
**`buildWithParameters`** over **HTTP Basic auth (user + API token)** — Jenkins's own documented
remote-build path, which needs no plugin and no webhook back-channel.

| Setting | Meaning |
| --- | --- |
| `THEMIS_COMMUNICATION_JENKINS_ENABLED` | off by default, and subordinate to `THEMIS_COMMUNICATION_DELIVERY_ENABLED` (M1a-7, M1b-1) |
| `THEMIS_COMMUNICATION_JENKINS_URL` | base URL; **must be `https`** |
| `THEMIS_COMMUNICATION_JENKINS_USER` | Jenkins user |
| `THEMIS_COMMUNICATION_JENKINS_API_TOKEN` | the user's API token — environment only, never a file, never a log (M1b-2) |
| `THEMIS_COMMUNICATION_JENKINS_JOB` | the job to build |

**`http://` is refused at CONFIGURE time**, with the one loopback exception, exactly as the Jira
sender already refuses it (M1b-2) and for the identical reason: the credential is in every request
and base64 is an encoding, not protection. The refusal keeps the FAKE sender wired and logs at ERROR
naming the variable (M1b-1), so the queue keeps draining and nobody mistakes "logging instead" for
"sending". A knob to relax this does not exist, because a knob that relaxes it in development is a
knob that can be set in production. Enabled-but-incomplete configuration behaves the same way.

As with Jira, the base URL may carry a path and every endpoint is built by APPENDING to it, so an
instance mounted at `/jenkins` needs no second code path.

The intent's snapshot is RC-3's, unchanged: destination job NAME, Product / Project / Release
identity, prior SBOM id, the targeted Finding set, the attempt index. **No credential, no key, no
model output.** Parameters handed to Jenkins are snapshot facts only.

### M2-7 — The job uploads, calls back, and the callback is evidence on the INTENT

The Jenkins job builds the image, uploads the new SBOM to Evidence against the same Product /
Project / Release under a new SBOM id, and then calls Themis back:

```
POST /api/v1/communication/callbacks/ci-rebuild
X-API-Key: <delivery:callback key>

{ "intent_id": "…", "build_id": "…", "git_ref": "…", "image_digest": "…", "sbom_id": "…" }
```

- The job's **upload** key is scoped **`product:<id>`** — the narrowest scope that can write
  evidence today. The CALLBACK key is `delivery:callback` and nothing else; D1/D2 keep it refused on
  every Governance write, unconditionally, however else it is minted.
- **Two keys, not one.** Uploading evidence and reporting a build are different acts with different
  blast radii, and a single key for both would mean the credential that may report a build may also
  write the estate's evidence.
- **The callback is governed-external evidence on the INTENT. It changes no Finding, no Position
  and no posture** — not even the Finding the rebuild targeted. A build system asserting a fix is
  asserted trust and is refused (D-N-4, D-N-7): only the evaluation of the uploaded SBOM can
  establish that a fault is absent, and that evaluation arrives as M2-1's events like any other.
- **No HMAC variant is built now.** D-N-6 allows one as a transport variant for a CI system that
  cannot present a Themis key; Jenkins can, so building a second authentication path would be
  carrying an untested credential mechanism for a case this estate does not have. The decision is
  "not now", not "never".
- `sbom_id` is the NEW SBOM's id, and it is REQUIRED alongside `image_digest` (RC-3). A callback
  missing either is refused: a rebuild whose output cannot be named gives the loop nothing to
  compare.

### M2-8 — The loop: compare after evaluation, one knob, stop and tell a person

The cycle, once per attempt, in this order and no other:

1. `ci_rebuild` intent → Jenkins → build → new SBOM uploaded → callback recorded (M2-6, M2-7).
2. Themis **evaluates** the new SBOM; `governance.release_evaluated.v1` fires with
   `cause: "new_sbom"` (M2-1).
3. Themis **compares** new against the immediately-previous SBOM (M2-5): which targeted Findings
   are closed, which are still open.
4. Themis **updates the Release's one Jira ticket** (RC-2 / M1b-4: counts for all four severities,
   CVE ids for Critical and High only, full-replace update) and **sends the mail** (RC-5).
5. Stop, or go round again.

Jira and mail happen at step 4 and **never at step 1 or 2**. The callback alone says a build
happened, which is not news about security.

**Loop control is one knob: `THEMIS_COMMUNICATION_REBUILD_MAX_ATTEMPTS`, default 2, with NO
per-Release override.** It closes RC-6's deferred name and locus. Communication owns the loop, so
the knob is Communication's and carries its prefix like every other delivery knob. A per-Release
override was considered and refused: it is a policy surface with no owner, no API and no audit
trail, and the first Release it is raised for is the one where the loop is already not working —
raising a limit is not a fix, and an estate-wide limit an operator can read in one line is worth
more than a per-Release one nobody can inventory.

The loop stops on exactly two conditions:

- **Success** — every Finding in the targeted Critical+High set is closed. Stop.
- **Exhaustion** — the attempt count reaches the maximum. Stop, and **tell a person**: mail to the
  governed audience plus a Jira update stating the attempts are exhausted and what is still open.

After a stop, **no further `ci_rebuild` intent is created for that Release in that cycle** — the
stop is the decision, not a pause. And in neither case is a Finding touched:
**Findings are NEVER auto-resolved** (RC-6, D-N-7). Resolution is a decision about exposure, not
about the existence of a fix, and it stays a human act. A failed attempt is an OUTCOME, not an
error: it is recorded, the Finding stays as it is, and the original Release stays affected.

### M2-9 — What N-M2 does not change

**N-M0 is unchanged** (RC-8, restated for the third time because this is the revision that finally
builds the things it guards): no new scope, no relaxation of the closed vocabulary, no new
Governance write path. `release_evaluated_events` is served by a **read** route under a read-scoped
key; the `ci-rebuild` callback is a **Communication** route under `delivery:callback`, which stays
refused on every Governance write. The scope vocabulary stays `admin` · `read` · `product:<id>` ·
`delivery:callback`.

Also unchanged: `ci_build` keeps its governance-controlled path (it carries an accepted change
artifact and follows `proposal_accepted`), the reader still writes intents and holds no outward
client (M1a-1), the payload is still materialized at enqueue (M1b-3), and secrets still come from
the environment and from nowhere else (M1b-2).

### Build steps — N-M2a..N-M2j

Each step is small, lands alone, and is testable alone. **Repo** is the repository that changes;
**API/schema** marks the two steps that touch a published surface or the database — everything else
is internal. Test names are the traceability handle, not a promise about file layout.

| Step | Repo | API/schema | What it builds | Test |
| --- | --- | --- | --- | --- |
| **N-M2a** | `themis` | — (bus contract) | Knowledge publishes `knowledge.release_correlation_completed.v1` once per SBOM, appended AFTER all its other events for that SBOM; `cause` carried through from the discovery path | `TestEventSchema_Knowledge_ReleaseCorrelationCompletedV1` (`internal/knowledge/adapters/store`) — schema, the ordering proof (the row's `seq` is greater than every other event for that SBOM), and the zero-match case |
| **N-M2b** | `themis` | — (bus contract) | Governance consumes it and publishes `governance.release_evaluated.v1`: snake_case fields, integer counts, `cause` mapped verbatim | `TestReleaseEvaluatedEvent_ZeroCounts_AndCauseMapping` (`internal/governance`) — zero counts emitted as success, both causes mapped, no third cause accepted |
| **N-M2c** | `themis` | — | Communication switches triggers: the `finding_opened` → ticket mapping is retired, and a ticket intent is created only on `governance.release_evaluated` with `cause=new_sbom` (product and project now populated) | `TestReleaseEvaluatedMapping_OnlyNewSBOM_CreatesIntents` + `TestFindingOpenedAndRediscovery_CreateNoIntents` (`internal/communication/adapters/inbound`) |
| **N-M2d** | `themis` | **API + schema** (migration up/down) | Governance table `release_evaluated_events` + the cursor read API `GET /api/v1/governance/events/release-evaluated?after=<sequence>&limit=<n>`; `limit` default 100 / max 500; response `items: [{seq, event_id, name, occurred_at, body}]` with the next cursor being the last item's `seq`; standard error mapping | `TestReleaseEvaluatedEventsCursorRead_AfterLimit_AuthMatrix` (handler table test: auth matrix, paging bounds, clamped limit, empty page) + migration up/down reversibility |
| **N-M2e** | `themis` | — | Comparison baseline: select the immediately-previous SBOM of the Release by upload order; detect closure of the targeted set | `TestSelectPreviousSBOM_ByUploadOrder` + `TestTargetedSetClosure_DoesNotGrowMidLoop` |
| **N-M2f** | `themis` | — | Jira update and mail emitted after the comparison only | `TestPostEvaluationOnly_ProducesTicketAndMail` + `TestCallbackAlone_NoSideEffects` (worker level; the update stays idempotent) |
| **N-M2g** | `themis` | — | `ci_rebuild` intent kind + the Jenkins `buildWithParameters` sender + `THEMIS_COMMUNICATION_REBUILD_MAX_ATTEMPTS`; HTTPS enforced at configure time | `TestCIBuildSender_BasicAuth_Params_HTTPSRefusal` (`httptest`: parameters, Basic auth header, `http://` refused with the fake kept) + config defaulting/override for the knob |
| **N-M2h** | `themis` | **API** | `POST /api/v1/communication/callbacks/ci-rebuild`, `delivery:callback` only, payload schema enforced | `TestCIRebuildCallback_AuthAndBodySchema` (every other scope refused, missing `sbom_id`/`image_digest` refused) + `TestCallback_NoFindingMutation` |
| **N-M2i** | `themis` | — | Stop conditions: success and exhaustion; no further `ci_rebuild` intent after a stop; exhaustion tells a person | `TestStopOnSuccessOrExhaustion_NoFurtherIntents` + `TestNotifyPersonOnExhaustion` (ticket + mail wording) |
| **N-M2j** | `themis-ai-runtime` | — | Harness poller: poll with `after=<sequence>` and `limit`, at-least-once, dedupe by event id, filter `cause=new_sbom`, persist a local high-water mark | `TestHarnessPoller_PollingWithCursor_AtLeastOnce_DedupeAndFilterNewSBOM` (`httptest` Governance stub: paging, a redelivered page proving dedupe is harmless, a `rediscovery` event ignored) |

The intent-type CHECK constraint that closes the vocabulary to `jira_issue` and `email` (M1a-9) is
widened to admit `ci_rebuild` in **N-M2g**, which is a schema change to a constraint rather than a
new surface; `ci_build` is still not added.

### The questions this revision closes

| Previously open | Decided |
| --- | --- |
| RC-1: event name(s) | `knowledge.release_correlation_completed.v1` + `governance.release_evaluated.v1` |
| RC-1: transport | Polling a Governance cursor read API. No SSE, no webhook, no long-lived connection |
| RC-1: subscriber auth | `X-API-Key`, **read** scope |
| RC-1: delivery semantics | At-least-once; dedupe by **event id** |
| RC-1: owning context | **Governance** (it owns the counts; Knowledge owns "correlation finished") |
| Cursor shape | The **sequence** number, never the event id |
| Paging bounds | `limit` default **100**, max **500** (clamped, not refused) |
| Event store | New Governance table **`release_evaluated_events`**; no purge/retention policy |
| Payload shape | **snake_case** field names; severity counts are **integers**; `cause` is a closed enum |
| RC-4: baseline | The **immediately-previous** SBOM of the Release by upload order. No window, no knob |
| Targeted set | Critical + High **at cycle start**; it does not grow mid-loop |
| RC-6: knob name and locus | `THEMIS_COMMUNICATION_REBUILD_MAX_ATTEMPTS`, default **2** |
| RC-6: per-Release override | **No.** Estate-wide only |
| `ci_rebuild` sender | Jenkins `buildWithParameters`, Basic auth (user + API token) |
| Jenkins URL scheme | **https mandatory**, refused at startup otherwise (loopback excepted) |
| Callback auth | `delivery:callback` only. **No HMAC variant now** |
| Callback payload | `{intent_id, build_id, git_ref, image_digest, sbom_id}` |

No open questions remain in N-M2's design.

### Honest limits (N-M2, as designed)

- **`product:<id>` is honoured but NOT confined at Evidence's upload route.** D3's confinement is
  Governance's, per Finding; the floor the other contexts mount (D5) answers `admin ∪ product:<id>`
  without resolving a resource. So the CI job's upload key is the narrowest scope that can write
  evidence, and it could in principle upload for another product. Narrowing the floor to the
  resource is a security-model change in five contexts and is deliberately NOT taken here — it is
  recorded so nobody relies on a confinement that does not exist.
- **The event is per SBOM, and a Release can have two SBOMs in flight.** Two uploads to one Release
  produce two evaluations and two events; the loop's attempt counter is per Release, so interleaved
  uploads can make an attempt's comparison baseline (M2-5) the OTHER upload. Upload order is still
  total, so the comparison is well defined — it is just not necessarily the pair a human had in mind.
- **A poll is lag.** A subscriber learns about an evaluation one poll interval late, and the interval
  is the subscriber's choice. That is the trade bought for having no inbound harness surface and no
  outward Themis credential, and it is the right one for a loop whose next step is a container build.
- **The cursor API serves a table that nothing prunes.** One row per evaluated SBOM is small, and
  the rediscovery sweep adds rows for Releases nobody is rebuilding. An estate will eventually want
  a retention policy; this revision deliberately does not invent one.
- **Two Communication nodes still race** (the N-M1b limit, now with a second edge): the per-Release
  lock is in-process, so two nodes can both create a `ci_rebuild` intent for one Release and spend
  two attempts on one. Closing it needs a store-level claim, which is its own step.
- **`cause` is producer-asserted.** A consumer cannot verify that a `new_sbom` event really followed
  an upload; it trusts Governance, which trusted Knowledge. The alternative — inferring the cause
  from SBOM identity at every consumer — replaces one trusted statement with N guesses.
- **Nothing here makes the harness able to act.** It reads; it is on the outside of every effect.
  That is by design, but it means a harness that notices something wrong can only report it.

### Realizes (planned — no code in this revision)

`internal/knowledge` (correlation-complete publication) · `internal/governance` (the
release-evaluated publication, `release_evaluated_events` + its migration, the cursor read route in
`api/governance.openapi.yaml`) · `internal/communication` (trigger switch, comparison, `ci_rebuild`
kind and Jenkins sender, the `ci-rebuild` callback route in `api/communication.openapi.yaml`, the
attempt counter) · `deploy/node.env.example` (the five Jenkins knobs + the attempts knob, commented
and valueless) · `themis-ai-runtime` (the poller, N-M2j). Conventions: R1 (console + OTel from the
one shared logger; no credential, address or payload in a log line), R2 (self-documented config,
secrets referenced). Runtime-side source: `themis-ai-runtime/openspec/changes/outward-actions`
(D-N-8..D-N-12 and the subscriber-seam lock).

## Revision 3 — N-M2a as built (2026-10-07): the completion event's BODY and its ordering mechanism

The first build step of **Revision 3 — N-M2** landed. **Accepted as a decision of record.
IMPLEMENTED.** This section is append-only like the rest of the file: nothing above it is amended,
and where it states something the N-M2a step row left open or said differently, **this later
section governs** — which is the convention the N-M2 section itself set out.

Two things needed deciding once code met the event, and both were taken by the owner in the N-M2a
implementation round: what the body carries, and how "appended AFTER every other Knowledge event
for that SBOM" is actually enforced.

**Provenance, because M2a-1 NARROWS the N-M2a step row's prose.** The step row and the build
instruction said the event carries product, project, release and SBOM ids; M2a-1 carries two of
the four. That is not an implementer's simplification: it is the owner's decision, taken in the
**N-M2a implementation round on 2026-10-07** ("introduce no Knowledge→Registry seam — remove
`product_id`/`project_id`; emit only release, SBOM, cause and time"), and this section is its
record of reference. **Cite it as `EDR-DELIVERY-01 M2a-1`** wherever the narrowing has to be
justified — a review of the diff alone cannot see the instruction, which is exactly why the
decision lives here rather than only in a task note. The same round fixed the two other shape
facts M2a-1 records (snake_case, `occurred_at` in the body) and left M2a-3's mechanism to the
implementation, where the second iteration of this step scoped it per SBOM.

### M2a-1 — The body is `{release_id, sbom_id, cause, occurred_at}`. It carries NO product or project id

```json
{
  "release_id":  "<uuid>",
  "sbom_id":     "<uuid>",
  "cause":       "new_sbom",
  "occurred_at": "2026-10-07T09:30:00Z"
}
```

`additionalProperties: false`, all four required, `cause` the closed enum of M2-3.

**The owner's decision was to leave product and project OFF this event**, and the reason is M2-1's
own division of labour. Knowledge does not know a release's product or project: identity lives in
Registry, and Knowledge holds **no Registry seam** — adding one to put two ids on an event would
be a new cross-context read in the context whose whole statement here is "I am done with this
SBOM". M2-2 keeps `product_id` and `project_id` on **`governance.release_evaluated.v1`**, where
they belong: Governance already reads Registry (the blast-radius multiplier, C2, over
`THEMIS_REGISTRY_URL`) and already owns the counts, so it is the context that can state the whole
fact. **N-M2b resolves them there** — that is now part of its scope, not an accident of it.

The consequence is deliberate and small: a direct subscriber to the *Knowledge* event cannot name
the product. Nothing subscribes to the Knowledge event but Governance (M2-1), and the published
surface a harness polls is Governance's (M2-4), which carries all four ids. So the shape nobody
reads is the narrower one.

Two further shape notes, both divergences from the older Knowledge events and both intentional:
field names are **snake_case**, matching M2-2 rather than Knowledge's own Go-field-name wire; and
`occurred_at` rides **in the body** as well as on the envelope, because N-M2d stores these events
and a stored fact that cannot say when it happened without its transport metadata is incomplete.

### M2a-2 — Published from the correlation WRITE phase, once per run, for `kind == "sbom"` only

The event is appended at the end of `ApplyCorrelation` — the single write phase BOTH paths share,
and the only place that knows every other event for the SBOM is already queued. The kind gate is
the coordinator's existing dispatch (`sbom` correlates; `vex` folds applicability; `scanner-report`
ingests), so a **VEX or scanner-report upload cannot reach the announcement** — it is not a check
bolted beside the publication, it is the dispatch that was already there.

It is **unconditional on the outcome**: zero items, or every item gated out of the reconciled
range, still correlated this SBOM (M2-1 — silence must mean a fault). It is skipped only when
there is no SBOM id to name, which is the same guard the KN-RECOR-1 ledger uses. The sweep states
`cause: "rediscovery"` explicitly rather than letting a consumer infer it (M2-3).

### M2a-3 — Ordering is enforced per SBOM, by the append position plus the relay's tie-break

Knowledge's outbox has **no sequence column** and the relay drains it `ORDER BY occurred_at`, so
"appended after every other Knowledge event for that SBOM" needs saying in terms of what the relay
can sort. Two local facts do it:

1. The row is appended **last in the unit of work**, carrying a clock reading taken after every
   other note of that correlation was stamped.
2. The relay sorts the completion **last within a shared instant**
   (`ORDER BY occurred_at, (event_type = 'knowledge.release_correlation_completed')`). A
   correlation reads the clock once per note, so a frozen or coarse clock can stamp a whole unit of
   work alike — and a tie is precisely where the outbox cannot settle the order by itself.

**The promise is scoped to the SBOM, and so is the mechanism.** A timestamp derived from the whole
outbox (`MAX(occurred_at)` over the unsent rows) was built first and rejected: it claims a global
last-in-outbox position nothing asked for, it reorders unrelated contexts' — and unrelated SBOMs' —
events behind one completion, and two concurrent transactions can still read the same MAX and pick
the same instant, so it does not even remove the tie it exists to remove. The tie-break does, for
the one relation that matters.

Honest limits, stated rather than engineered around:

- **A wall-clock STEP BACKWARDS inside one unit of work would break the order.** The completion's
  timestamp is read last, so only a clock that moves backwards mid-correlation (an NTP step, not
  drift) can put it before a note of its own run. The fix for that is a sequence column, which is a
  migration and is not in N-M2a's scope.
- **Two completions sharing one instant are unordered with respect to each other.** They are
  different SBOMs, and the contract says nothing about their relative order.
- **"Every other Knowledge event for that SBOM" means that correlation RUN.** A feed enrichment
  that touches one of the same cards a second later is a separate unit of work and can be delivered
  after the completion. That is correct — it is news about a card, not an unfinished correlation —
  but a consumer must not read the completion as "this release's cards will not change again".

### M2a-4 — Still no consumer, no API, no schema

Nothing reads the event yet: Governance picks it up in **N-M2b**. No OpenAPI edit, no generated
handler, no migration, no new dependency, and `cmd/knowledge` is untouched — the announcer is wired
where the store is already in hand (`internal/knowledge/adapters/wiring`), with no toggle, because
an event nothing consumes needs no switch and an unwired producer would be silent in exactly the
way M2-1 forbids.

### Realizes (N-M2a)

`internal/knowledge/domain/event.go` (`ReleaseCorrelationCompleted` + the closed `DiscoveryCause`
vocabulary) · `internal/knowledge/app` (the `CorrelationAnnouncer` port, `CorrelationPlan.Cause`,
`CorrelateCause`, the sweep's cause) · `internal/knowledge/adapters/store`
(`AnnounceCorrelationCompleted`, the pinned `schema_ref`, the frozen v1 schema under `schemas/`,
the relay's tie-break) · `internal/knowledge/adapters/wiring` (`WithCompletion`). Tests:
`TestEventSchema_Knowledge_ReleaseCorrelationCompletedV1` (schema, both halves of the per-SBOM
ordering, the shared-instant regression, zero-match, both causes, and VEX/scanner-report publishing
nothing) plus app/domain unit tests. Tracked as task **6.1** in
`openspec/changes/phase3-outward-actions/tasks.md`.
