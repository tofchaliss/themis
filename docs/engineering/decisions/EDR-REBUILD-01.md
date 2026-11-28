# EDR-REBUILD-01 — A policy decides the image rebuild, a signed event carries it, a build connector starts it

Status: **PROPOSED — 2026-11-26. Step R1 built 2026-11-27 and step R1a (API) built 2026-11-28**,
each on the owner's go; every later step is design only. The owner picked the form factor on 2026-11-26 (choice 1 below: signed event plus
build connector) and accepted the picks of choices 2, 3 and 4 on 2026-11-27. Choice 5 carries an
assumed pick and is asked again at step R5. Feature work stays behind the release freeze: each
step needs the owner's go.
**Revision 2, 2026-11-26:** the owner chose to keep the build configuration in Themis, as a build
profile per Project and Release (D10). D10 replaces the mapping part of D8.
**Revision 3, 2026-11-27:** after an outside review the owner chose a policy per installation,
Product and Release (D11). Five clarifications from that review are decided as D12 to D16. A
second review the same day gave D17 to D21; the owner decided that the policy is the ceiling for
automation and a tag can only restrict it (D17). A third review, of revision 3, gave D22 to
D26; the owner decided who may approve in mode `ask` (D22). A fourth review, of D1 to D26,
gave D27 to D32; they align decisions already taken and add no new owner choice. A fifth
review, of D1 to D32, gave D33 to D36, again with no new owner choice. A sixth review, of D1
to D36, gave D37 and D38: the connector's stored states with recovery after a restart, and the
word `submitted` in place of `started`. No new owner choice. A seventh review, of D1 to D38,
gave D39: one worker per intent in the connector, and when "no build found" may be believed.
No new owner choice. An own read of D1 to D39 against each other, asked by the owner the same
day, gave D40 to D43 and three corrections in place (D4, D8, D10). A review of D40 to D43 gave
D44 (the states of a recommendation, and one standing recommendation enforced by the database)
and one more correction in D8. No new owner choice. A review of D44 gave D45: approval only
while the effective mode is exactly `ask`, and what the notice rule does and does not promise.
A review of D45 gave D46: the approval against a policy or tag change at the same moment, and
expiry before withdrawal. A review of D46 added the expiry notice rule to D46 item 1, and the
owner accepted the tag limit of D46 item 9 (choice 10).
Date: 2026-11-26
Author: the design discussion of 2026-11-26 (thread "Plan policy-driven image rebuild trigger").

## Purpose

The owner's ask (2026-11-26): Themis starts an image build for one Product / Project / Release
when that release matches the right configuration **and** a configurable policy says a build is
needed. The policy decides whether the trigger is given. The owner also notes that this feature
is tightly bound to each enterprise's own build setup, and asks for a form factor that keeps
that binding out of Themis.

This record builds on EDR-DELIVERY-01 (the rebuild loop), EDR-INCIDENT-01 D1 (the fix-available
event) and EDR-REMEDIATION-01 D4 and D7 (webhooks and tags). It replaces nothing in them except
where a decision below says so.

## What Themis has today (measured 2026-11-26, main `ee9ad7e`)

1. **The rebuild loop is built** (EDR-DELIVERY-01 RC-3, M2-6, M2-7, M2-8), in Communication.
   A `new_sbom` evaluation that leaves open Critical or High Findings opens a cycle. A
   `ci_rebuild` intent goes to Jenkins (`buildWithParameters`). The job uploads the new SBOM and
   calls back. Themis compares, updates the ticket and the mail, and stops on success or after
   `THEMIS_COMMUNICATION_REBUILD_MAX_ATTEMPTS` (default 2).
2. **The rule that opens a cycle is fixed in code**: any open Critical or High. It does not ask
   whether a fix exists, whether the Finding was decided, or whether the component carries the
   flaw.
3. **One build target for the whole installation**: `THEMIS_COMMUNICATION_JENKINS_JOB`. The job
   gets product, project and release ids as parameters and must do its own routing.
4. **Only a new SBOM starts a cycle.** A vendor fix published later raises
   `governance.fix_available.v1` and a notification, but no build.
5. **Only Jenkins**, with Basic auth, wired inside the Communication node.
6. **Signed webhooks exist** (EDR-REMEDIATION-01 D4): per-audience targets, an HMAC-SHA256
   signature in `X-Themis-Signature`, routes per event and per release tag.
7. **Tags exist** on Product, Project and Release (EDR-REMEDIATION-01 D7), inherited downward.

## What the market offers (survey, 2026-11-26)

No product covers "governed decision, then policy, then rebuild of one named release". The survey
is from public documentation; nothing was tested.

| Group | Examples | What it does | What it lacks for this ask |
| --- | --- | --- | --- |
| Rebuild on base image or package change | Freshmaker, registry build tasks with base-image triggers, platform image-change build triggers | Rebuilds images when an advisory ships or a base image moves | No policy over Findings; bound to one build system or one cloud |
| Scanner with policy and actions | Artifact scanners with watches and policies, image analysis services with remediation pull requests, SBOM analysis platforms | Policy on severity and fix; action is a webhook, a ticket or a pull request | The rebuild is left to the customer's CI; no knowledge of decisions taken elsewhere |
| Cloud image factories | Cloud image pipelines fed by the cloud's own scanner over its event bus | A finding becomes a cloud event that starts a pipeline | One cloud only; the policy is an event filter |
| Dependency update bots | Version update bots | A pull request when a newer base tag or digest exists | Driven by versions, not by vulnerabilities or policy |
| Patch without rebuild | In-place image patchers, daily rebuilt hardened base images | Patch OS packages in an existing image, or supply fresh bases | OS packages only; the customer's own image still needs a build |

Two open building blocks fit the chosen form factor: the CloudEvents and CDEvents formats, and
the webhook receivers most CI systems already have (generic webhook triggers, pipeline trigger
APIs, event listeners).

What only Themis holds: the per-release Position, vendor statements with applicability, carrier
versus scope attribution, and the compare-after-rebuild loop that proves a fix.

## Decisions

### D1 — Themis decides, the customer side builds (owner choice 1, 2026-11-26)

Themis owns the **decision** that a release needs a rebuild and the **loop** that checks the
result. It does not own how an enterprise builds. The decision leaves Themis as one signed
event. A separate **build connector** on the customer side receives it, maps the release to a
pipeline, and starts the build with credentials that never enter Themis.

Alternatives refused:

- **More senders inside Themis** (one per CI system). Every customer build system becomes core
  code. This is the coupling the owner wants out.
- **Policy and trigger fully outside** (an external rule engine reads Themis APIs). A second
  place would decide about security, and the stop rule and comparison of M2-8 would be lost.
- **The AI runtime starts the build.** EDR-DELIVERY-01 RC-7 stands: Themis owns every outward
  effect and the AI advises only.

A pull transport (the connector polls a read API, as the harness poller does for
`release_evaluated`) is **not built now**. It is the answer for an enterprise that allows no
inbound call to its CI network, and it can be added behind the same event body.

### D2 — A rebuild policy with fixed fields replaces the fixed rule (assumed pick, choice 2)

The policy answers one question for one release: **is a rebuild worth asking for now?** It is a
record with fixed fields, not a script.

| Field | Meaning | Default |
| --- | --- | --- |
| `fix_required` | count a Finding only when a fixed version is known for its component | yes |
| `severity_floor` | lowest severity that counts | high |
| `count_known_exploited` | count a Finding in KEV whatever its severity | yes |
| `skip_decided` | do not count Findings whose Position is `not_affected` or `accepted_risk` | yes |
| `carrier_only` | do not count scope-class components (EDR-CORRELATION-01); unknown counts as carrier | yes |
| `cool_down` | shortest time between two rebuild requests for one release | 24h |
| `mode` | `auto` (request at once) or `ask` (tell a person first, D5) | ask |

A release with at least one counted Finding gets a rebuild request. The counted Findings are the
**targeted set** of the cycle, in place of "Critical plus High at cycle start" (M2-5). The set
still does not grow inside a cycle.

`fix_required = yes` is the main change in behaviour. A rebuild of an image for which no fixed
package exists changes nothing and burns an attempt.

A rule language (CEL, Rego) was considered and not taken: fixed fields can be read by an auditor
in one screen, need no new dependency, and cover every case named so far. The decision is "not
now".

### D3 — What makes Themis evaluate the policy

1. `governance.release_evaluated.v1` with `cause: "new_sbom"` (as today).
2. `governance.fix_available.v1` (EDR-INCIDENT-01 D1): a vendor fix now exists for open rows of
   the release. **New.** This is the case the loop misses today.

A `rediscovery` evaluation still never starts a cycle and never advances an attempt
(EDR-DELIVERY-01 M2-3, unchanged). A fix-available trigger does not break that rule's reason:
the attempt is spent only when a build is asked for, and a fix is exactly the news that makes a
build worth asking for.

`governance.disposition_stale.v1` is **not** a trigger. A stale decision re-opens a question for
a person; a build does not answer it.

### D4 — Which releases are in scope: opt-in by tag

A release is in scope only when it carries the tag **`rebuild:auto`** or **`rebuild:ask`**, its
own or inherited from its Project or Product (EDR-REMEDIATION-01 D7). No tag means no rebuild
request, ever. The tag `rebuild:off` on the Release, its Project or its Product always wins
(corrected to match D17 item 3; the first text said only a release-level `off` wins).

This uses a tag as a filter, which D7 allows. It does not weight priority. One honest limit: a
`product:<id>` key may edit tags, so a product team can opt its own releases in. That is the
intended owner of this choice.

The installation-wide switch stays: with the rebuild feature off, tags do nothing.

### D5 — Mode `ask`: a person confirms before the first build of a cycle

In mode `ask`, Themis sends the notification "rebuild recommended" (ticket section, mail, webhook
route `rebuild_recommended`) and creates no build request. A person starts the cycle from the
GUI or the API. Later attempts in the same cycle follow the loop without asking again.

`ask` is the default because a build that starts by itself in an enterprise pipeline is an
outward effect, and the first weeks should show what the policy would have done.

### D6 — The event: `rebuild_requested`, signed, in CloudEvents shape

Communication sends the request on the existing webhook channel to the audience routed for
`rebuild_requested` (tag routes apply, so two products can go to two connectors).

Body facts, all from the intent snapshot (EDR-DELIVERY-01 M1a-8: no credential, no model
output):

```json
{
  "specversion": "1.0",
  "type": "themis.rebuild.requested.v1",
  "id": "<intent id>",
  "time": "<RFC 3339>",
  "source": "themis/communication",
  "data": {
    "product_id": "<uuid>", "product_name": "example-product",
    "project_id": "<uuid>", "project_name": "project-a",
    "release_id": "<uuid>", "release_version": "<version>",
    "prior_sbom_id": "<uuid>",
    "decision_id": "<uuid>", "cycle_id": "<n>", "attempt": 1, "try": 1, "max_attempts": 2,
    "reason": "fix_available",
    "policy_version": "<n>", "policy_scope": "product",
    "build_profile_revision": "<n>", "build_profile_scope": "project",
    "build_profile_sha256": "<hex>",
    "targeted": [ {
      "finding_id": "<uuid>", "cve": "CVE-0000-0000", "purl": "<purl>",
      "current_version": "<version>", "fixed_version": "<version>", "fix_source": "<feed>",
      "severity": "high", "score": 8.1, "score_source": "<source>",
      "known_exploited": false, "claim_class": "carrier",
      "position": "none",
      "counted_because": ["severity_floor"],
      "assessment": { "state": "assessed", "revision": "<n>" }
    } ],
    "build": { }
  }
}
```

- `build` is the release's build profile, copied as stored (D10, revision 2).
- Which fields of a targeted entry are required is fixed in D34.
- The signature is the existing `X-Themis-Signature: sha256=<hex>` over the body. A
  `rebuild_requested` route **without** a signing secret is refused at configure time: an
  unsigned request to build is not sent.
- Targets are `https` only, as for every webhook.
- The event is a request, not a command. The connector may refuse (freeze window, missing
  mapping); it reports that through the callback as a **refusal**, which is not an attempt
  (D20).

The Jenkins sender of M2-6 stays as it is. An installation uses the Jenkins sender **or** the
event route for a given release, never both; the route wins when both are configured, and the
startup log says so.

### D7 — The callback and the loop do not change

The pipeline uploads the new SBOM under the same Release and calls
`POST /api/v1/communication/callbacks/ci-rebuild` with a `delivery:callback` key (M2-7). The
loop compares after evaluation and stops on success or exhaustion (M2-8).
`THEMIS_COMMUNICATION_REBUILD_MAX_ATTEMPTS` stays installation-wide; M2-8's refusal of a
per-release limit stands.

A build system still cannot close a Finding. Only the evaluation of the new SBOM can.

### D8 — The build connector is a separate program, outside this repository (assumed pick, choice 5)

> **Revision 2 (2026-11-26):** the mapping no longer lives in the connector. D10 puts it in
> Themis as a build profile. The connector keeps the credentials and the last step only.

The connector is small: verify the signature, run the checks of D18 on the build profile the
event carries, start the pipeline, nothing else. It holds the CI credentials and its own
allow-lists. It owns no security decision and no Finding state. It **does** keep stored
working state: the event records, their states, the claim and the build identity, for
duplicate detection, recovery and status reports (D12, D37, D39). (The first text said "it
keeps no security state", which read as "no state".)

- It lives in its own repository so that an enterprise can fork or replace it without touching
  Themis.
- The reference connector supports **one build system first** (corrected to match D33 item 5
  and D39 item 5; the first text named three generic cases). Others follow as own connectors.
- ~~A CI system that can verify an HMAC webhook itself needs no connector at all.~~
  **Withdrawn**, see D42.
- It holds no mapping from release to job. The job and its parameters come from the build
  profile in the event (D10); the connector only decides whether they are allowed (D18).

### D9 — Where the policy lives and who evaluates it (assumed picks, choices 3 and 4)

**Governance evaluates.** The fields of D2 are Governance facts (Position, fix known, exploit
signals, claim class). Governance publishes `governance.rebuild_requested.v1` or
`governance.rebuild_recommended.v1`; Communication consumes it, keeps the cycle, and delivers.
Today Communication opens the cycle from a posture read; that rule moves, the cycle stays.

**The policy is stored in Governance's database, one policy per installation at first**, with a
read and a write route (admin only), the version number carried on every request, and each
change recorded with the actor. An environment-file policy would be faster to build, but a
policy that can start builds needs an owner and an audit trail, which is the same reason M2-8
gave.

> **Revision 3 (2026-11-27):** D11 replaces "one policy per installation" with three levels.

### D10 — The build profile: a JSON block per Project and Release, stored in Themis (owner, 2026-11-26, revision 2)

The owner's question: which Jenkins configuration is pushed, and can it be a JSON configuration
set per project and release in Themis. Answer: yes.

1. **Registry stores one build profile per Project.** A Release inherits its Project's profile
   and may carry its own, which replaces the Project's as a whole (no field-by-field merge: a
   merged profile is one nobody wrote).
2. **The profile is opaque to Themis.** It must be a JSON object. Themis does not read inside
   it and no Themis rule depends on a key in it. It is copied as stored into the `build` field
   of the `rebuild_requested` event (D6). This is what keeps build-system knowledge out of
   Themis core while the configuration sits beside the release it belongs to.
3. **No secrets.** The profile is shown in the GUI, returned by the read API and sent in an
   event. Credentials stay on the build side. Themis refuses a profile with a key named like a
   secret (`password`, `token`, `secret`, `api_key`, `credential`, any case, any depth). That
   check is a guard against mistakes and not proof; the rule is stated on the form.
4. **Bounded.** At most 16 KiB and 5 levels deep.
5. **Who may write it:** `admin`, or the Product's own `product:<id>` key, as for tags. Each
   change is recorded with actor and time, and the previous value is kept.
6. **No profile, no request.** A release in scope by tag (D4) with no profile, own or
   inherited, gets no `rebuild_requested`. Themis sends the "rebuild recommended" notification
   with the reason "no build profile", so the gap is seen.
7. **The profile is frozen on the request.** The value is copied into the intent snapshot when
   the request is created. A later edit changes the next request, not one already sent.

A suggested shape, which Themis does not enforce:

```json
{
  "job": "team/build-image",
  "parameters": {
    "BRANCH": "release/<version>",
    "BASE_IMAGE_TAG": "latest",
    "REGISTRY_PATH": "<registry>/project-a"
  }
}
```

The connector reads `data.build.parameters` as the job parameters and the other `data` fields
as facts. The same block serves any other build system; only its keys differ. (The first text
let a Jenkins job with a webhook trigger read the event directly. That is withdrawn, see D42.)

What remains for the connector (D8): verify the signature, hold the credentials, start the job
that `build` names, **after the checks of D18**. A person who can edit a profile could otherwise
name any job the connector's credential can start.

The Jenkins sender of M2-6 keeps its seven fixed parameters and does not read the profile.

### D11 — Policy scope: installation, Product, Release (owner, 2026-11-27, revision 3)

This replaces "one policy per installation at first" in D9 and removes the per-Product and
per-Release policy from the list of things not decided.

1. **Three levels.** One installation policy always exists. A Product may have its own. A
   Release may have its own.
2. **The nearest one wins, as a whole.** Release, else Product, else installation. There is no
   Project level and **no field-by-field merge**: the policy in force for a release is always
   one record that one person wrote, never a mix.
3. **The effective policy is readable.** `GET` on a release returns the policy in force and the
   level it came from. One list read returns every policy in the installation with its scope,
   so all of them fit on one page. This is the answer to "a per-release setting nobody can
   inventory" (EDR-DELIVERY-01 M2-8).
4. **Each policy has its own version counter** and its change history with actor and time. The
   event carries `policy_version` and `policy_scope`.
5. **Who may write:** the installation policy, `admin` only. A Product or Release policy,
   `admin` or that Product's `product:<id>` key.
6. **The attempt limit is not a policy field.** `THEMIS_COMMUNICATION_REBUILD_MAX_ATTEMPTS`
   stays installation-wide (M2-8 stands).
7. **Tags still decide scope** (D4): a tag says whether a release takes part, the policy says
   when a rebuild is worth asking for. Which of the two sets the **mode** is decided in D17.

Build order: the installation policy first (R1), then Product and Release overrides (R1a).

### D12 — One request starts at most one build (revision 3)

Themis delivers at least once and always repeats a request with the **same event id** (the
intent id). The rest is the receiver's duty and part of the connector contract:

1. The connector keeps a durable record per event id. It writes the **event record** before
   it calls the build system, and the **outcome record** after the build system answers. D37
   names the states.
2. An event id already recorded as submitted is acknowledged and submits nothing.
3. An event id whose event record exists but whose outcome record is missing (a crash between
   the call to the build system and the outcome record) is **not** sent again blindly. The connector first asks the build system for a build that
   carries this intent id. If it cannot tell, it reports the attempt as `uncertain` through the
   callback and a person decides.
4. The reference connector passes the intent id to the job as a parameter, so that step 3 can
   find it.

The same limit already stands for the built-in Jenkins sender (`buildWithParameters` is not
idempotent); this decision does not change that sender.

### D13 — One open cycle per Release, enforced by the database (revision 3)

Governance publishes the request through its transactional outbox, and Communication consumes
it through its inbox, idempotent on the originating event id (EDR-DELIVERY-01 M1a-2). New in
this record: `rebuild_cycles` gets a **unique rule: at most one open cycle per Release**. A
second request for a release with an open cycle joins that cycle and creates nothing.

This also closes the two-node race listed under the honest limits of EDR-DELIVERY-01 and of
this record.

Governance does not publish the same request twice either. How a request is identified is
decided in D23.

### D14 — The cool-down counts from a successful dispatch (revision 3)

1. The cool-down of D2 starts when the `rebuild_requested` event was **delivered** (the
   receiver answered with success).
2. A retry of the same request is never held back by the cool-down. It is the same intent.
3. A request that could not be delivered and was given up does **not** start the cool-down.
   The give-up notice goes to a person as for every delivery.
4. The cool-down gates the **opening of a new cycle** only. Attempt 2 inside an open cycle
   follows the loop (M2-8) and is not delayed.
5. A request held back by the cool-down is not lost: the policy is evaluated again at the next
   trigger, and the held-back state is shown on the release.

### D15 — What an approval records in mode `ask` (revision 3)

1. A recommendation freezes what the person is asked to approve: the release, the targeted
   Findings, the policy scope and version, the build profile revision.
2. The approval records the **actor, the time, the decision id of the recommendation** (D27)
   and those frozen facts. The request that follows carries exactly them. No cycle exists yet
   at approval time; the cycle is opened after it and points back to the approval.
3. A policy or profile change after the recommendation does not alter it. The next cycle uses
   the new values.
4. A recommendation nobody answered **expires after 7 days**. It is evaluated afresh at the
   next trigger.
5. Only a person may approve; the AI cannot. Which key may carry the approval is decided in
   D22.

### D16 — The request names the build profile it used (revision 3)

The event carries `build_profile_revision`, `build_profile_scope` (`project` or `release`) and
`build_profile_sha256` (over the stored bytes) beside `policy_version` and `policy_scope`, and
the `cycle_id` that ties all attempts and callbacks together. Each targeted entry names its
Finding and the facts the decision used for it (D29); nothing has to be rebuilt from a
timestamp. With the intent id, these fields answer "which policy
and which configuration authorized this build" from the event alone. D10 item 5 already keeps
every earlier profile value, so a revision can be read back.

### D17 — The policy is the ceiling for automation; a tag can only restrict (owner, 2026-11-27)

Before this decision the mode had two authorities, the policy field `mode` (D2) and the tag
(D4), and revision 3 first let the tag win. That is withdrawn. A tag and a Product or Release
policy can be written with a `product:<id>` key; only the installation policy is `admin` only.
So only the installation policy may allow automatic builds.

The modes are ordered **`off` < `ask` < `auto`**. The effective mode of a release is the
**lowest** of three values:

1. the `mode` of the **installation** policy (the ceiling),
2. the `mode` of the policy in force for the release (D11), when that is a Product or Release
   policy,
3. the release's tag: `rebuild:off` on the Release, its Project or its Product always gives
   `off`; otherwise the nearest of `rebuild:auto` / `rebuild:ask` (Release, then Project, then
   Product); no tag gives `off` (D4).

| Installation policy | Tag | Effective mode |
| --- | --- | --- |
| `auto` | `rebuild:auto` | `auto` |
| `auto` | `rebuild:ask` | `ask` |
| `ask` | `rebuild:auto` | `ask` |
| `ask` | `rebuild:ask` | `ask` |
| any | `rebuild:off` or none | `off` |

With a Product or Release policy in force (all three values, lowest wins):

| Installation policy | Policy in force | Tag | Effective mode |
| --- | --- | --- | --- |
| `auto` | Product: `ask` | `rebuild:auto` | `ask` |
| `auto` | Release: `auto` | `rebuild:ask` | `ask` |
| `ask` | Product: `auto` | `rebuild:auto` | `ask` |
| `auto` | Product: `off` | `rebuild:auto` | `off` |
| `auto` | Product: `auto` | `rebuild:auto` | `auto` |

A policy's `mode` may therefore also be `off` (D2 listed `auto` and `ask` only): a Product or
Release policy can switch rebuilds off for its scope whatever the tags say.

The effective-policy read of D11 item 3 returns the effective mode and which of the three
values set it.

### D18 — The connector must authorize the job; the signature is not enough (revision 3)

The signature proves that the event came from Themis. It does not prove that the job named in
`build` is allowed for that Product. These checks are a **required** part of the connector
contract, and the reference connector refuses to start without them configured:

1. An allow-list of jobs, **per Product and Project**. A job not listed for the event's
   Product and Project is refused.
2. An allow-list of parameter **names** per job. An unknown name is refused, not dropped.
3. Value checks per parameter, from a schema per job (D31).
4. A build-system credential that can start only the listed jobs, restricted **in the build
   system itself** (D33).
5. Replay checks: the event id must be new (D12), the `type` must be known, and the `time`
   must not be older than the connector's limit (default 24 hours, which is longer than
   Themis's delivery retries).

A refusal under this decision is reported as in D20. The profile configures an approved job; it
does not grant the right to run one.

### D19 — What "a fix is known" means for `fix_required` (revision 3)

A Finding counts under `fix_required` only when all of these hold for **that component
occurrence in that release**:

1. Knowledge holds a fixed version for the same package identity and the same ecosystem or
   distribution as the matched component (the per-world range of EDR-KNOWLEDGE-01 D13). A fix
   published for another distribution, or for the source package with no mapping to this binary
   package, does not count.
2. The release's version of the component is below that fixed version, by the comparison rule
   of D30.
3. While `carrier_only` is on (D2): the component is a carrier, or its claim class is unknown.

This is the same per-package fact that raises `governance.fix_available.v1`
(EDR-INCIDENT-01 D1). Each targeted entry carries the Finding id, the purl, the current and
fixed version and the feed that stated the fix (D6).

Themis does **not** know whether the fixed package is in the enterprise's own build
repository, or whether the build profile picks it up. If it is not, the build runs, the
comparison shows the Finding still open, and the loop stops at the attempt limit.

### D20 — A refusal is not an attempt (revision 3)

Three counters are kept apart:

| Counter | Counts | Limit |
| --- | --- | --- |
| delivery retries | tries to hand one event to the receiver | the existing delivery budget |
| refusals | answers "not submitted" from the connector (freeze window, job not allowed, D18) | 3 per cycle |
| attempts | builds the build system accepted (`submitted`, D38), plus requests whose outcome is still open (D28) | `THEMIS_COMMUNICATION_REBUILD_MAX_ATTEMPTS` (2) |

1. An attempt is **reserved** when the request is delivered and **used** when the build system
   has accepted the build (D38); a refusal **gives it back**. D28 has the full table.
2. A refusal is recorded on the cycle with its reason, and a person is told.
3. After a refusal the request is made again at the next trigger, or by a person.
4. After 3 refusals the cycle stops as `refused`, and a person is told. Nothing is retried
   without end.
5. An `uncertain` outcome (D12 item 3) keeps the attempt counted until a person settles it.

### D21 — A new fix during an open cycle waits for the next cycle (revision 3)

A `fix_available` or `new_sbom` trigger for a release with an open cycle joins that cycle
(D13) and does not change its targeted set. When the cycle closes, the policy is evaluated
once more for the release, so Findings that qualified in the meantime start the next cycle,
subject to the cool-down (D14).

### D22 — Who may approve in mode `ask`: admin or product key, with a named person (owner, 2026-11-27)

The owner's choice follows the rule that already holds for a decision on a Finding.

1. The approval call must carry a **named human actor**. A call without one is refused. The
   actor, the key's id and its scope are recorded with the approval (D15).
2. The key may be `admin`, or `product:<id>` for the release's own Product.
3. `delivery:callback` and `read` keys can never approve. The AI can never approve.

**Honest limit, stated because it was weighed.** A key is a credential, not a person. The
actor name is asserted by the caller; Themis has no user login to check it against. And the
build job holds a `product:<id>` key to upload its SBOM (EDR-DELIVERY-01 M2-7), so a job that
was changed to do so could approve a rebuild for its own Product. Two things keep this narrow:

- **Use two product keys**: one for the CI job, one for the people who decide. The runbook
  says so, and the approval record shows which key approved, so a CI key approving is visible.
- The approval can only start a build of a job the connector allows for that Product (D18),
  for a release an admin-owned policy lets build at all (D17).

When Themis gets user logins with roles, the approval moves to a human identity and this
decision is revisited.

### D23 — Four identities, so that an equal request later is a new request (revision 3)

Keying a request on the release, the policy version and the targeted set (D13, first draft)
would treat a later, legitimate request with the same inputs as a duplicate. Four ids are kept
apart:

| Id | Made when | Unique per |
| --- | --- | --- |
| trigger id | an event of D3 arrives, or a cycle closes (D21) | one evaluation of the policy |
| decision id | Governance decides "request" or "recommend" for a trigger | trigger id |
| cycle id | Communication opens a cycle | one open cycle per Release (D13) |
| intent id | one attempt is to be delivered | cycle id, attempt number and try number (D40) |

Duplicates are found on the **trigger id**: the same trigger delivered twice yields one
decision. A new trigger always yields a new decision, even with the same policy version and the
same Findings. Whether that decision opens a cycle is then a matter of D13 (a cycle is open)
and D14 (the cool-down), not of equality with an earlier request. The event carries the
decision id, the cycle id and the intent id.

### D24 — Settling an uncertain build is recorded (revision 3)

When the connector cannot tell whether a build was submitted (D12 item 3), the cycle shows
`uncertain` and waits. A person settles it through the API or the GUI with one of two answers,
`submitted` or `not_submitted`, under the same rule as D22. The answer, the actor and the time are
recorded on the cycle. `not_submitted` gives the attempt back (D20) and the request may be sent
again; `submitted` keeps it. A build system with no way to search by intent id always ends here,
and that is acceptable.

### D25 — Delivered is not built: the words Themis uses (revision 3)

A successful answer to the event means only that the receiver took it. The GUI, the ticket, the
mail and the audit record use these states for one attempt and never a stronger word than the
evidence allows:

| State | Evidence |
| --- | --- |
| `requested` | the intent exists |
| `delivered` | the receiver answered with success |
| `submitted` | the connector reported that the build system accepted the build and gave it an identity (D38) |
| `refused` / `uncertain` | the connector said so (D20, D12) |
| `build_reported` | the callback arrived with image digest and SBOM id (M2-7) |
| `evaluated` | the new SBOM was evaluated and compared (M2-8) |

The receiver answers with success only after it has stored the event (D12 item 1). The
cool-down still counts from `delivered` (D14).

### D26 — An expired recommendation is an event, and starts nothing (revision 3)

When a recommendation passes its 7 days (D15 item 4), Themis records
`rebuild_recommendation_expired` on the release and tells a person on the
`rebuild_recommended` route. The release shows "recommendation expired" until its next trigger.
Expiry never approves and never builds. No timer re-evaluates the release; the next trigger of
D3 does.

### D27 — A recommendation is identified by its decision id; the cycle comes after approval (revision 3)

D5, D15 and D23 together left one gap: an approval was said to record "the cycle", but in mode
`ask` no cycle exists until a person approves. The decision id of D23 closes it. It is made by
Governance for every trigger that ends in "request" or "recommend", so **a recommendation is a
decision with outcome `recommend`, and its decision id is its identity**. No fifth id is needed.

1. Governance evaluates, records a decision with outcome `recommend`, and freezes the facts of
   D15 on it.
2. A person approves **that decision id** (D22). The approval is recorded on the decision.
3. Governance publishes the request, carrying the decision id and the approval.
4. Communication opens the cycle (D13) and gives it a cycle id. The cycle stores the decision
   id it came from.
5. Each attempt gets its intent id.

A recommendation that expires (D26) or is never approved has a decision id and no cycle. In
mode `auto` step 2 is skipped and the rest is the same.

**Where a trigger id comes from.** For a bus event of D3 it is that event's own id together
with its source context, so a redelivered event is the same trigger. For a cycle closure (D21)
the id is generated and stored **in the same transaction** that closes the cycle, so a crash
and a replay cannot evaluate the closure twice.

### D28 — When an attempt is reserved, used and given back (revision 3)

D20 said both "builds that were accepted" and "counted when delivered"; D25 then showed that
delivered is not built. This table is the one rule and replaces both sentences.

| What Themis learns | State (D25) | The attempt is |
| --- | --- | --- |
| the intent is created | `requested` | not touched |
| delivery fails and is given up | — | not touched |
| the receiver stored the event | `delivered` | **reserved** |
| the connector refuses | `refused` | given back |
| the connector reports the build system accepted the build | `submitted` | **used** |
| the connector cannot tell | `uncertain` | still reserved, until a person settles it (D24) |
| a person settles `not_submitted` | — | given back |
| a person settles `submitted` | `submitted` | used |
| the build callback arrives | `build_reported` | used (if not already) |

1. A reserved attempt counts against the limit while it is open. So a cycle never has more
   requests in flight than attempts left.
2. The connector reports `submitted`, `refused` or `uncertain` with one small status call on the
   existing callback route, under the `delivery:callback` key, naming the intent id. It changes
   no Finding, as every callback (M2-7).
3. A reservation with no status and no build callback after the connector's time limit
   (default 24 hours, the same as D18 item 5) is shown as `uncertain` and handled by D24.
4. The cool-down still counts from `delivered` (D14).

### D29 — The request carries the facts the decision used (revision 3)

Positions are append-only, but the calculated assessment of a component can change with no new
Position (a new vendor observation, a changed range, a calculator revision). So the request
does not rely on reading history back. Each targeted entry carries, as decided:

- the Finding id, the purl, the current and fixed version, the fix source (D19),
- the severity and score used and their source, the known-exploited flag, the claim class,
- the state of the Position (none, or which stance),
- the state of the component assessment (EDR-SCORING-01) and its revision when there is one;
  what a missing revision means is fixed in D35.

These are frozen on the decision (D15) and copied to the intent snapshot. The decision record
in Governance is the audit copy; the event is the transport copy.

### D30 — "Below the fixed version" is Knowledge's verdict, not a new comparison (revision 3)

Version order depends on the ecosystem (RPM epoch-version-release, Debian, Maven, Python, Go,
distribution backports). Governance does **not** compare version strings for this policy.

1. The verdict "this occurrence is below its fixed version" comes from Knowledge's
   per-ecosystem comparison, the same one that gates a match and decides the version-range
   rule (EDR-KNOWLEDGE-01 D13, D14).
2. Where Knowledge cannot read a version or cannot order it (`value.VersionParsable` is false,
   or no range for this component's world), the answer is **unknown**, and unknown is **not** a
   known fix. The Finding stays open and counts for nothing under `fix_required`.
3. This is the opposite default from attribution, on purpose: an unknown carrier is treated as
   a carrier so that a flaw is not hidden, while an unknown fix starts no build so that a build
   is not wasted. Neither hides the Finding.

### D31 — A parameter schema per job, and values are never joined into a command (revision 3)

This replaces the generic "type, length, a pattern" of D18 item 3. For each allowed job the
connector configuration holds a schema:

1. the exact parameter names (D18 item 2),
2. for each name its type, its length limit and its own rule (a branch name, an image tag and a
   registry path are checked differently),
3. how a list or a structured value is passed, if the job takes one.

The connector passes values to the build system **as parameters through its API**. It never
builds a shell command or a script from event values. The reference connector has a test that
tries a value with command syntax against each built-in rule.

The least-privilege credential (D18 item 4) is checked against the build system, not only
declared. How, and what happens when the check fails, is decided in D33.

### D32 — Expiry is found by a sweep that evaluates nothing (revision 3)

D26 says what expiry is; this says what notices it. A sweep in Governance, on the cadence of
the existing review-by sweep (`THEMIS_REVIEW_BY_INTERVAL`, default 1h), finds recommendations
older than 7 days, records `rebuild_recommendation_expired` once per decision id, and tells a
person. It does not evaluate the policy, approve or build. The next trigger of D3 evaluates.

### D33 — The credential is narrow in the build system, and the connector fails closed (revision 3)

D31 said the connector "warns loudly" when its credential can reach a job outside the
allow-list. A warning does not stop that credential from being used, so it did not deliver what
D18 item 4 promised. Corrected:

1. **The limit lives in the build system.** The connector's credential is given the right to
   start the allow-listed jobs and nothing else, with the build system's own permissions (a
   folder or project scoped role, a token bound to one pipeline). The connector's allow-list is
   a second check, not the boundary.
2. **The startup check asks, it does not try.** The reference connector queries the build
   system for the credential's permissions. It never starts a job to find out.
3. **It fails closed.** If the check shows the credential can start a job outside the
   allow-list, the connector **does not start**. The same when the check cannot be run.
4. **One stated exception.** Where a build system cannot express a narrow enough permission,
   the operator may set an explicit setting that accepts a broader credential. The connector
   then logs that fact at every start, and its status page shows it. In that setup the
   allow-list in connector code is the only limit, and this record does **not** call the
   credential least-privileged. That is a residual risk the enterprise accepts by setting it.
5. **The check is written per build system.** Permission models differ between build systems
   and are not interchangeable. The reference connector carries the check for the one build
   system it supports. A connector for another build system writes its own check against that
   system's model, and items 1 to 4 hold for it unchanged.

### D34 — The targeted entry: which fields are required (revision 3)

The example in D6 now shows every field of D29. One targeted entry is **one matched component
of one Finding**.

| Field | Required | Note |
| --- | --- | --- |
| `finding_id`, `cve`, `purl` | yes | |
| `current_version`, `fixed_version`, `fix_source` | yes | a request exists only with a known fix (D19) when `fix_required` is on; with it off, `fixed_version` and `fix_source` may be `null` |
| `severity`, `score_source` | yes | the severity the policy compared with its floor, and where it came from |
| `score` | nullable | `null` when the source gave a level and no number |
| `known_exploited` | yes | `true` or `false` |
| `claim_class` | yes | `carrier` or `unknown`; a `scope` component is never targeted under `carrier_only` |
| `position` | yes | `none`, or the stance in force |
| `counted_because` | yes, not empty | the policy fields that made it count: `severity_floor`, `known_exploited` |
| `assessment` | yes | see D35 |

**Identity of an entry.** Within one request the pair (`finding_id`, `purl`) is unique: a
Finding lists each matched component once, and the purl carries the version. Step R2 must
confirm that against Governance's stored component list before the event contract is fixed. If
one Finding can hold the same purl twice, an occurrence index is added to the entry then; a
purl alone is never taken as the identity.

### D35 — What a missing assessment revision means (revision 3)

`assessment.state` is always present and takes one of three values. `revision` is present only
with the first.

| `state` | Meaning | `revision` |
| --- | --- | --- |
| `assessed` | a component assessment exists and its severity was used | present |
| `not_assessed` | no component assessment exists yet; the source severity of the CVE was used | absent |
| `not_eligible` | the component is outside the assessment (for example scope-class); cannot occur in a request while `carrier_only` is on | absent |

There is no fourth, silent state. With `counted_because`, the versions and the severity source,
an entry says by itself why the component was targeted, whether or not a revision exists.

### D36 — One intent, one payload, byte for byte (revision 3)

The decision record in Governance is the audit copy and the event is the transport copy (D29).
To keep the two from drifting:

1. The event body is **built once**, when the intent is created, from the frozen decision. It
   is stored on the intent as bytes with its SHA-256. This is the existing rule that a payload
   is materialized at enqueue and a sender never renders (EDR-DELIVERY-01 M1b-3), now stated
   for this event.
2. Every delivery try of that intent sends **exactly those bytes**. Nothing is read again from
   Governance, Knowledge or Registry for a retry, so a feed update or a calculator change
   between two tries cannot change what is sent under one event id.
3. The signature (D6) is over those bytes, so it is the same on every try.
4. The connector may store the hash with its event record (D12) and refuse a second delivery
   of a known event id whose body differs.

### D37 — The connector's stored states, and recovery after a restart (revision 3)

D12 asks for a stored record before the build call, D25 lets the connector answer with success
once the event is stored, and D28 reserves the attempt on that answer. One case was left open:
the connector stores the event, answers with success, and stops before it calls the build
system. Themis does not send again, because it got a success. Nothing in D12 told the connector
to pick the event up again. Decided:

| Stored state | Meaning | After a restart |
| --- | --- | --- |
| `received` | the event is stored and checked (D18); the build system was not called yet | continue: go to `submitting` |
| `submitting` | written just before the call to the build system | never call again blindly: first ask the build system for a build that carries the intent id (D12 item 3) |
| `submitted` | the build system accepted the build and gave it an identity (D38) | never submit again; report again if the report was not confirmed |
| `refused` | a check of D18 failed, or the build system said no | report again if the report was not confirmed |
| `uncertain` | the question in `submitting` could not be answered | report again; a person settles it (D24) |

1. **The rule.** A success answer to the event is a promise. Every stored event ends in
   `submitted`, `refused` or `uncertain`, and that end is reported to Themis (D28 item 2). No
   stored event is dropped in silence.
2. **A recovery worker is required.** At start, and then on a timer, the connector scans its
   records for `received` and `submitting`, and for end states whose report Themis has not
   confirmed, and carries each one forward by the table.
3. **`submitting` found after a restart:** a build with the intent id exists → `submitted`. The
   build system answers and has none, **and that answer may be believed (D39 item 5)** → back
   to `received`, and the build is submitted. In every other case → `uncertain`.
4. **The status report is repeated until Themis answers with success.** Themis takes a
   repeated report of the same state for the same intent id as a no-op.
5. **Two records, named.** The *event record* is written at `received`. The *outcome record*
   is the move to `submitted`, `refused` or `uncertain`. D12 item 3 means a crash between the
   call and the outcome record.
6. **Themis keeps its own guard.** If the connector loses its store entirely, D28 item 3 still
   applies: a reservation with no status after the time limit shows as `uncertain` and goes to
   a person. So a lost build request is seen from both sides.

This is part of the connector contract of step R5 and of its tests: stop the connector in each
state, start it, and check the end state and the build count.

### D38 — `submitted` is the counting point, not execution (revision 3)

D20 said "builds that started", D25 and D28 said "the build system took the build". A build
system can accept a request, put it in a queue, and run it later or never. The two moments are
now kept apart:

| Word | Evidence | Role |
| --- | --- | --- |
| `submitted` | the build system accepted the request and returned an identity (a queue item or a run id) | **the attempt is used here** |
| `execution_started` | the build system says the build is running | optional, shown only |

1. **The attempt is used at `submitted`.** A build that waits in a queue counts. So a cycle
   cannot send a second request while the first one waits.
2. **The state of D25 and D28 is renamed from `started` to `submitted`**, and with it the
   status value of D28 item 2 and the answers of D24 (`submitted` / `not_submitted`). D12, D20,
   D24, D25 and D28 above carry the new word.
3. **`execution_started` is optional information.** The connector may send it with the same
   status call. Themis shows it and counts nothing from it. A build system that does not
   report it loses nothing.
4. **A build that was accepted and then cancelled, or that failed before it ran, stays a used
   attempt.** It ends as the loop already ends a build with no result (M2-8); the attempt is
   not given back. Giving it back would let a queue that keeps cancelling ask without end.
5. **The identity returned at `submitted` is kept** on the connector's record and sent in the
   status call, so that a person can find the queued build.

### D39 — One worker per intent, and when "no build found" may be believed (revision 3)

D37 added a recovery worker that scans the records. Themis may also deliver one event twice
(D12). So two workers, or two connector instances, can see the same record in `received` and
both call the build system. The intent id as a job parameter (D12 item 4) lets a build be
found; it does not stop a second one. Decided:

1. **The rule.** For one intent id the connector makes at most one submission call at a time,
   and never a second one while the result of the first is not known.
2. **The claim is one conditional write.** The move `received` → `submitting` is a single
   compare-and-set in the connector's store (in SQL: an update that names the old state, and
   exactly one row changes). The worker that wins holds the claim. Every other worker, and
   every second delivery of the same event, sees `submitting` and makes no call. The store
   must be shared by all instances of one connector; a store per instance is not allowed.
3. **The claim carries an owner, a counter and an end time.** The counter goes up by one with
   every new claim. The outcome record (D37 item 5) is also a conditional write that names the
   counter, so a worker that lost its claim cannot write an outcome.
4. **An expired claim does not allow a new call.** A claim whose time has passed is taken over
   only for the question of D37 item 3, never for a direct call. The call to the build system
   has a hard time limit that is shorter than the claim, and the take-over waits for the end
   of the claim plus a margin. So the old worker's call is over before the question is asked.
5. **"No build found" is believed only where the build system makes it true.** Per build
   system the connector states whether its search is complete: it must cover waiting builds
   (the queue) as well as running and finished ones, and must show a build as soon as the
   request was accepted. Complete → "none" means not submitted, and the record goes back to
   `received`. Not complete, or not stated → `uncertain`, and a person settles it (D24). The
   reference connector states this for its one build system and tests it.
6. **Where the build system has an idempotency key, the intent id is sent as that key.** Then
   the build system itself refuses a second submission, and that is the stronger guard. The
   job parameter of D12 item 4 stays as well, for the search.
7. **What is and is not promised.** With an idempotency key in the build system: one intent,
   at most one accepted build. Without one: the connector cannot make that a proof, because a
   request may be accepted by the build system after the caller gave up. Items 2 to 5 close
   every path the connector controls, and what is left ends in `uncertain`, not in a silent
   second build. A second build, if one ever happens, is seen: two build callbacks for one
   intent id, and Themis records the second and counts no new attempt (M2-7 rule: a callback
   changes no Finding).

Tests of step R5 for this decision: two workers and two instances on one `received` record
give one call; a worker stopped inside the call, then a take-over, gives no second call before
the question; an outcome write with an old counter is refused.

### D40 — A request made again gets a new intent id (own review)

D23 made the intent id unique per cycle and attempt number. D20 gives the attempt back after a
refusal, and D24 after a person settles `not_submitted`, and both say the request is made
again. With the same attempt number that would be the **same intent id**. The connector already
holds that id as `refused` or `uncertain` (D37) and would do nothing with it. Decided:

1. Each attempt number has a **try number**, starting at 1. A request made again after a
   refusal or after `not_submitted` keeps the attempt number and takes the next try number.
2. The intent id is unique per cycle id, attempt number and try number. So a request made
   again is a **new event** for the connector, with a new stored record.
3. The event carries `attempt` and `try` (D6).
4. The new intent builds its own payload once (D36), from the same frozen decision. The facts
   do not change inside a cycle (D21).
5. The limits do not move: at most 3 refusals per cycle (D20), and the attempt limit counts
   attempt numbers, not tries.
6. A delivery retry is not a try. It repeats the same intent id (D12).

### D41 — One standing recommendation per Release (own review)

In mode `ask` every trigger makes a new decision (D23), and no cycle exists yet to join (D13).
So five `fix_available` events in a week would leave five open recommendations for one release.
Decided:

1. A release has **at most one standing recommendation**.
2. A new trigger whose result has the same targeted set, policy version and profile revision
   as the standing recommendation records a decision with outcome `unchanged`. It points to
   the standing one. Nobody is told again.
3. A new trigger with a different result makes a new recommendation. The old one is marked
   `superseded`, and a person is told once about the new one.
4. Only the standing recommendation can be approved. An approval of a superseded or expired
   decision id is refused, with the id of the standing one in the answer.
5. The 7 days of D15 count from the standing recommendation's own time.

D44 fixes the states, what ends "standing", and how "at most one" is enforced.

### D44 — The states of a recommendation, and how "one standing" is kept (review of D41)

D41 left three things open: whether an expired recommendation is still the standing one, what
stops two triggers from creating two, and what a change of mode does to it.

**States.** A recommendation is in exactly one:

| State | Meaning | Can be approved |
| --- | --- | --- |
| `standing` | the one open recommendation of the release | yes |
| `approved` | a person approved it (D22); the request was published | no |
| `superseded` | a later trigger gave a different result (D41 item 3) | no |
| `expired` | 7 days passed with no answer (D15) | no |
| `withdrawn` | a later trigger found nothing to ask for, or the mode is no longer `ask` | no |

Every state except `standing` is final.

1. **Expired means no longer standing, by the clock.** A recommendation older than 7 days is
   not standing from that moment, whether or not the sweep of D32 has marked it yet. The
   evaluation and the approval both check the time themselves. The sweep only records the
   event and tells a person.
2. **So the next trigger after expiry makes a new recommendation**, even with the same
   targeted set, policy version and profile revision, and a person is told. The `unchanged`
   outcome of D41 item 2 exists only against a recommendation that is standing now.
3. **The comparison of D41 item 2 includes the effective mode** (D17). If the mode is now
   `off`, or the evaluation finds nothing to count, the standing recommendation becomes
   `withdrawn` and nothing new is made. If the mode is now `auto`, it becomes `withdrawn` and
   the request is published directly, as `auto` does.
4. **The database keeps "at most one".** Governance's store has a unique rule: one `standing`
   recommendation per Release (the same means as D13 for cycles). Ending the old one, creating
   the new one and writing the notice to the outbox happen in **one transaction**.
5. **Two triggers at once.** The transaction that loses on the unique rule creates nothing and
   sends nothing. It evaluates again against the recommendation that won and applies D41
   (`unchanged` or supersede). What this promises about notices is corrected in D45 item 2.
6. **Approval is one conditional write**, `standing` → `approved`, that also checks the 7 days
   and that the effective mode is still exactly `ask` (corrected in D45 item 1; the first text
   said "not `off`"). Of two approvals at once, one wins; the other is
   refused as in D41 item 4.
7. **After approval and until the cycle closes, no new recommendation is made** for the
   release. A trigger in that time joins the cycle (D13, D21). Governance learns that the
   cycle closed from the closure trigger (D21, D27) and evaluates then.

### D45 — Approval only in mode `ask`; one notice per recommendation (review of D44)

1. **Approval needs the effective mode to be exactly `ask`, now.** D44 item 6 checked only that
   the mode was not `off`. If the mode changed to `auto` and no trigger had evaluated the
   release yet, a person could still approve the old recommendation, beside the direct path of
   D44 item 3. Corrected: the approval computes the effective mode (D17) at that moment and
   succeeds only for `ask`. The mode check, the 7 days and the move `standing` → `approved` are
   one conditional write in one transaction.
2. **When the approval is refused for the mode,** the same transaction moves the
   recommendation to `withdrawn` and records an evaluation trigger for the release (a trigger
   id as in D27). The normal evaluation then decides: `off` does nothing, `auto` publishes the
   request directly. The approval call itself never starts a build in that case. Its answer
   says which mode is in force.
3. **The notice promise, stated exactly.** D44 item 5 said "only one notice leaves". That is
   true only when the second trigger's result is `unchanged`. If it differs, it supersedes the
   first recommendation and sends its own notice, and the first notice may already be out.
   The promise is: **one notice per recommendation that was created**, never two for the same
   one, and none for an `unchanged` result.
4. **A notice that replaces another says so.** It names the recommendation it supersedes. No
   notice is called back or held: a person may see two notices close together, and the second
   one is the valid one.
5. **A late notice cannot mislead into a wrong approval.** Every notice names its decision id,
   and an approval of a decision id that is not standing is refused with the id of the
   standing one (D41 item 4).

### D46 — Approval against a change at the same moment; expiry comes first (review of D45)

D45 put the mode check and the state change in one transaction. A transaction alone does not
stop a policy change that commits between the read and the write. And the three inputs of the
effective mode (D17) do not live in one place: the two policies are in Governance's database,
the tags are in Registry and are read over the read seam.

**Order of the checks in an approval.** First the 7 days, then the mode.

1. **Expiry comes first.** If the 7 days have passed, the approval is refused and the
   recommendation is recorded as `expired`, whatever the mode is now. A fact about time is not
   overwritten by `withdrawn`. The expiry event of D26 is recorded once, by the approval or by
   the sweep, whichever sees it first. **Whichever records it also writes the notice**: the
   move `standing` → `expired`, the event and the notice to the outbox are one transaction, in
   the approval path exactly as in the sweep (D32). The move is a conditional write, so only
   one of the two can make it, and the other finds `expired` and writes nothing. One expiry,
   one event, one notice. Nothing else follows; the next trigger evaluates (D26).
2. **Only a recommendation still inside its 7 days is checked for the mode**, and D45 item 2
   (`withdrawn`, with an evaluation trigger) applies to that case only.

**The policy part is exact.**

3. Every policy has a version counter (D11 item 4). The approval reads the installation policy
   and the policy in force **with a lock that blocks a write to them** until the approval
   commits (in SQL: `SELECT ... FOR SHARE` on those rows, in the approval's transaction). A
   policy write waits, or the approval waits for it. So a policy change that committed before
   the approval is always seen, and none can slip between the check and the state change.
4. Creating or deleting a Product or Release policy for that release takes the same lock path
   (it locks the installation policy row first), so "which policy is in force" cannot change
   under the approval either.
5. The approval record stores the policy versions it checked (D15).

**The tag part is as exact as two stores allow.**

6. The approval reads the tags **fresh from Registry** inside the approval call. No cached
   value is used.
7. **It fails closed.** If Registry cannot be read, the approval is refused and the
   recommendation stays `standing`. This is on purpose the opposite of the blast-radius read,
   which falls back to a neutral value: here the read authorizes a build.
8. The approval record stores the tag values it read and the time of the read.
9. **Honest limit.** A tag changed in Registry in the instant between that read and the
   approval's commit is not seen. No transaction spans the two stores, and this record does not
   add one. The result is the same as if the approval had come an instant earlier, and the
   record shows which tag values it rested on. The installation policy, the only input that
   can **raise** the mode (D17), is in the exact part. **The owner accepted this limit on
   2026-11-27 (choice 10).** A second tag check in Communication before the first event is
   sent was offered and not taken: it narrows the window and cannot close it.

**After the approval.**

10. The request that Governance publishes carries the policy versions and the tag values of
    the approval. Nothing is evaluated again between approval and publication; they are one
    transaction through the outbox (D13).
11. A change to `off` **after** an approval does not call back a request already published.
    Whether `off` should stop a cycle that is already open is not decided here; it is listed
    under what this record does not decide.

### D42 — Every receiver of `rebuild_requested` meets the connector contract (own review)

D8 said a CI system that can verify the signature "needs no connector at all", and D10 let a
build job read the event directly. Later decisions made that false. A receiver must keep the
allow-lists (D18), report `submitted`, `refused` or `uncertain` (D28), keep the stored states
(D37) and the claim (D39). A plain webhook trigger does none of these. Decided:

1. Both sentences are withdrawn (marked in D8 and D10).
2. Whatever receives `rebuild_requested` must meet the whole connector contract: D12, D18,
   D28 item 2, D31, D33, D37, D39. It may be the reference connector, a fork, or code inside a
   build system. The name does not matter; the contract does.
3. A receiver that never sends the status call is not harmful but is slow: every request
   becomes `uncertain` after the time limit (D28 item 3) and waits for a person.

### D43 — What the built-in Jenkins sender does under this record (own review)

D6 keeps the sender of M2-6 for installations with no `rebuild_requested` route. The record did
not say which new rules reach it. Decided:

1. **Policy, tags, modes, approval, cool-down, one cycle per Release and the four ids apply.**
   They are decided before any sender is chosen (D9).
2. **The build profile does not apply** (D10). The sender keeps its seven fixed parameters and
   the one configured job.
3. **States.** The sender calls the build system itself, so `delivered` and `submitted` are
   one moment: the build system answered the call with success. There is no `refused` from a
   connector. A call whose result is not known is `uncertain` and goes to D24.
4. The connector-side decisions (D18, D31, D33, D37, D39) do not apply. Its known limit stays:
   the call is not idempotent (D12).

## Choices for the owner

| # | Choice | Assumed pick | State |
| --- | --- | --- | --- |
| 1 | Form factor | signed event plus build connector | **answered 2026-11-26** |
| 2 | Policy language | fixed fields (D2) | **answered 2026-11-27** |
| 3 | Where the policy is stored | Governance database with API and audit (D9) | **answered 2026-11-27** |
| 4 | Default mode | `ask` (D5) | **answered 2026-11-27** |
| 5 | Where the connector lives | its own repository (D8) | open; asked again at R5 |
| 6 | Where the build configuration lives | in Themis, per Project and Release (D10) | **answered 2026-11-26** |
| 7 | Policy scope | installation, Product and Release, nearest wins as a whole (D11) | **answered 2026-11-27** |
| 8 | Mode: policy against tag | the installation policy is the ceiling, a tag only restricts (D17) | **answered 2026-11-27** |
| 9 | Who may approve in mode `ask` | `admin` or the Product's key, with a named person (D22) | **answered 2026-11-27** |
| 10 | A tag changed in the instant of an approval | accept the limit of D46 item 9; no second check | **answered 2026-11-27** |

## Order of work (proposed; each step alone, on the owner's go)

| Step | What | Touches |
| --- | --- | --- |
| R0 | this record and the backlog item | docs |
| R1 | policy record, evaluation in the domain, read and write API | Governance domain, API, migration |
| R1a | Product and Release policy overrides; the effective-policy read and the list read (D11). API built 2026-11-28; the GUI page follows as `GUI-REBUILD-POLICY-1` | Governance domain, API, migration; GUI |
| R2 | evaluation on `new_sbom` and on `fix_available`; the two new events; tag scope. Built in two parts: part 1 (2026-11-28) is tag scope, effective mode and the judgement as a read; part 2 is the triggers, the stored decision and the events | Governance, Registry read seam; part 1 also adds one read to Knowledge |
| R2a | build profile on Project and Release: storage, history, read and write API, the secret-name and size checks, a GUI form | Registry domain, API, migration; GUI |
| R3 | Communication consumes the events; the cycle opens from them; `rebuild_requested` and `rebuild_recommended` webhook routes; signed-only rule; the status call, attempt reservation, refusal counter and try number (D20, D28, D40); settling `uncertain` (D24) | Communication, API |
| R4 | mode `ask`: the "start rebuild" action in API and GUI; one standing recommendation and its states (D41, D44, D45, D46); the expiry sweep (D32) | Governance or Communication API, GUI |
| R5 | reference build connector, with the durable event record of D12, the stored states and recovery worker of D37, the per-intent claim of D39, and the required checks of D18 | new repository |
| R6 | VM check: one release tagged, one fix published, one build, one comparison | test VM |

R1 changes the domain model and an API, R3 changes event contracts, R5 is a new repository. Each
is on the "must ask" list.

### Step R1 as built (2026-11-27)

The owner gave the go for R1 on 2026-11-27. The tasks are in
`openspec/changes/phase3-image-rebuild`.

- **Domain** (`internal/governance/domain/rebuild_policy.go`). The record has the seven fields of
  D2. The shipped default is: fix required, floor `high`, known exploited counts, decided
  Findings and scope components do not count, cool-down 24 hours, mode `ask`. The modes are
  ordered off < ask < auto, and a mode the code cannot read is treated as `off`, so an unknown
  value never allows a build. `EvaluateRebuild` is a pure function: it takes the policy and the
  candidates (one matched component of one open Finding, with its severity bucket, its known
  exploited mark, its Position, its claim class and Knowledge's fix verdict of D30) and returns
  the counted components with `counted_because` (D34). It compares no version strings and reads
  no clock.
- **Store** (Governance migration 28). `rebuild_policies` holds the policy in force, one row per
  scope, with a version that counts the changes from 1. `rebuild_policy_history` holds every
  version with who changed it and when. A change writes both in one transaction. The scope
  columns are there from the start, so R1a needs no second table.
- **API.** `GET /rebuild-policy` (read scope; the defaults at version 0 when nothing is stored),
  `PUT /rebuild-policy` (admin only; `updated_by` is required; every field is required, because a
  switch left out and read as `false` would loosen the policy without anybody choosing it),
  `GET /rebuild-policy/history` (newest first).
- **Not in R1.** Nothing evaluates a Release, nothing is published and no build is asked for. The
  rule gets its trigger in R2. Product and Release policies are R1a. The cool-down is stored and
  not yet applied (D14 applies it when a cycle opens).
- **The cool-down is stored in whole seconds**, from 0 to one year. The upper bound only stops a
  typing mistake.
- **VM check PASSED 2026-11-28** (task 1.6, main `dc39448`, auth on, admin key). Governance
  restarted and applied migration 28. Before any change the policy read version 0, mode `ask`,
  floor `high`, cool-down 86400 seconds, and the history was empty. Two changes gave versions 1
  and 2. A change without `fix_required` was refused with HTTP 400 and "fix_required is
  required", and stored nothing. A third change set the starting values back as version 3. The
  history then showed versions 3, 2, 1, each with the actor and the time. Not tried on the VM:
  a read-only key on `PUT` (no such key is at hand there); the refusal is covered by the handler
  tests.
- **Found in the VM check, fixed 2026-11-28:** the answer to a change carried the time in
  nanoseconds and the history carried it in microseconds, the database's precision. The service
  now cuts the time to the microsecond before storing, so both read the same. Checked on the
  VM the same day (main `2087d83`): the answer to a change and the read after it both carried
  `2026-11-28T06:00:19.605258Z`, version 4.

### Step R1a as built (2026-11-28)

The owner gave the go for R1a on 2026-11-28. This step is D11: a policy per Product and per
Release beside the installation policy.

- **Domain.** `ResolveRebuildPolicy` picks the policy in force for one Release: the Release's
  own, else its Product's, else the installation's. The record is taken whole (D11 item 2). It
  also returns the **mode ceiling**: the lower of the installation policy's mode and the mode
  of the policy in force (D17 values 1 and 2), and which of the two set it. A Product or
  Release policy can lower the mode and cannot lift it above the installation's.
- **Store** (Governance migration 29). The table of migration 28 holds all three levels. The
  migration names the three scope kinds, ties the scope id to the kind, and adds `removed` to
  the history. The version of a scope is now counted from its history under a lock per scope,
  so it keeps counting when a policy is removed and set again.
- **Removing a policy.** D11 did not say how a Product or Release goes back to the level above.
  As built: `DELETE` removes the policy in force and writes one history entry with
  `removed: true`, the removed values, the actor and the time. The installation policy cannot
  be removed.
- **API.**
  - `GET /rebuild-policies`: every policy in force on one page, installation first (D11 item 3).
  - `GET` / `PUT` / `DELETE /products/{id}/rebuild-policy` and `.../history`.
  - `GET` / `PUT` / `DELETE /releases/{id}/rebuild-policy` and `.../history`.
  - `GET /releases/{id}/rebuild-policy/in-force`: the policy that applies, its level and
    version, the installation mode, `mode_ceiling` and `mode_set_by`.
- **Who may change** (D11 item 5): `admin`, or the `product:<id>` key of the Product concerned.
  For a Release the Product is read from Registry; when it cannot be established, a product key
  is refused (fail-closed). Reads need the read scope.
- **The in-force read fails closed.** When the Product of the Release cannot be read it answers
  503. It never shows the installation policy in place of a Product policy that could not be
  looked up.
- **`mode_ceiling` is not yet the effective mode.** D17 has a third value, the Release's tags,
  and a Release with no rebuild tag takes no part (D4). Tags are read from step R2 on. Until
  then the answer carries `tags_applied: false`, and D17's "which of the three values set it"
  is answered for two of the three.
- **Honest limits of this step.** Governance does not check that a Product id exists in
  Registry, and it does not check a Release id when an `admin` writes. A policy written for an
  id that does not exist applies to nothing; it shows on the list read and can be removed.
- **Not in R1a.** The GUI page for the policies (backlog `GUI-REBUILD-POLICY-1`). Nothing
  evaluates a Release and no build is asked for; that is still R2.
- **VM check PASSED 2026-11-28** (task 2.4, main `f90b036`, auth on, admin key; one Product,
  two Releases of two of its Projects). Governance applied migration 29. In order:
  1. Before any change both Releases took the installation policy, ceiling `ask`.
  2. A Product policy with mode `off` and floor `medium` got version 1. Both Releases then took
     it: level `product`, ceiling `off`, set by `policy`.
  3. A Release policy with mode `auto` and floor `low` on the first Release got version 1. That
     Release took its own policy whole (floor `low`), and its ceiling was `ask`, set by
     `installation`: the Release asked for `auto` and the installation's `ask` held (D17).
  4. The second Release still took the Product policy.
  5. The list showed three entries: installation, product, release.
  6. Both removals answered `removed: true` as version 2 with the actor. The Product history
     showed the removal first, then version 1.
  7. After the removals the first Release was back on the installation policy.
  Every answer carried `tags_applied: false`. Not tried on the VM: a `product:<id>` key (none is
  at hand there); the handler tests cover who may change.

### Step R2 part 1 as built (2026-11-28)

The owner gave the go for R2 on 2026-11-28. R2 is built in two parts. **Part 1 is the judgement
as a read**: Themis can say, for one Release, whether a rebuild would be asked for and for which
components. It stores nothing, publishes nothing and starts nothing. **Part 2** is the two
triggers (D3), the stored decision (D27, D29) and the two events (D9).

- **Knowledge: one new read** (an API addition in a second context, told to the owner before
  building). `GET /releases/{id}/fix-verdicts` returns every live occurrence of the Release
  with its recorded verdict and a `fix` value: `known` (open, and below at least one vendor
  bound for its own package and world), `none` (already cleared, or compared and no bound on
  record) or `unknown` (Themis could not compare). It serves what the occurrence verdict
  already recorded (`verdict_behind`, EDR-INCIDENT-01 D1). Nothing is judged or written. This
  is D30 as built: Governance orders no version strings.
- **Tags** (D4, D17 value 3). `ResolveRebuildTag` reads the own tags of the Release, its Project
  and its Product, from Registry's tag reads `GET /<kind>/{id}/tags` (no Registry change). `rebuild:off` on any
  level wins. Otherwise the nearest level with `rebuild:ask` or `rebuild:auto` decides. A level
  carrying both reads `ask`, because a tag only restricts. No rebuild tag is `off`.
- **Effective mode** (D17 whole). The lowest of the installation mode, the mode of the policy in
  force and the tag, with which of the three set it. When the tag and the policies give the same
  mode, the policy side is named. A Release with no tag reads "set by `tag`": the missing tag
  is what keeps it out. `GET /releases/{id}/rebuild-policy/in-force` now carries `tag`,
  `effective_mode`, `effective_mode_set_by` and `tags_applied: true`.
- **The judgement.** `GET /releases/{id}/rebuild-evaluation` (read scope). It looks at every
  open component occurrence of every Finding that is not resolved or archived, applies the
  policy in force, and returns: the policy, the tag, the effective mode, the `outcome`
  (`none`, `recommend` for mode ask, `request` for mode auto), each counted component with the
  fields of D34, and `skipped`: how many occurrences did not count, by the first rule that left
  each out (`decided`, `scope_component`, `no_fix`, `fix_unknown`, `below_floor`). A Release
  whose mode is `off` still shows what would count; its outcome is `none`.
- **Failure directions.** Registry unreadable (Product or tags): 503, no judgement. A tag list
  that could not be read never reads as "no tag". Knowledge unreadable: the read still answers,
  `fix_verdicts_read` is false, every fix is unknown, so nothing counts under `fix_required`.
- **D34 identity confirmed.** `finding_components` has the primary key (finding id, purl), so
  the pair is unique and no occurrence index is needed.

**Where part 1 differs from the decisions, and why. Each is open for part 2.**

1. **A known fix exists only for RPM and APK components.** Knowledge records the bounds an
   occurrence is below only where its fixed-verdict compares: RPM (same EL major) and APK. A
   language package (npm, Go, Maven, PyPI) reads `unknown` and so never counts while
   `fix_required` is on. That is the safe direction of D30. Widening it is Knowledge work
   (backlog `KN-FIX-STANDING-LANG-1`).
2. **`fixed_versions` is a list, not one `fixed_version`.** An occurrence can be below several
   bounds (two errata, or a module stream beside the plain build). Governance may not order
   them (D30). Part 2 must decide how the event names one, or keep the list.
3. **`fix_source` is `knowledge_verdict`, not a feed name.** The match row does not store which
   feed stated the bound, and the advisory is computed, not stored. Part 2 decides whether
   Knowledge stores it.
4. **Severity is the score priority and the SLA read, not the component assessment.** The
   calculated assessment is in shadow (EDR-SCORING-01 9.1: computed and shown, not used). So
   `score_source` is `base_score`, or `owner_set` when a person set the severity, and
   `assessment.state` is `not_assessed` (or `not_eligible` for a scope component). `assessed`
   comes with the shadow exit (S7).
5. **A stale decision still counts as decided.** A `not_affected` or `accepted_risk` Position
   that was re-surfaced is still skipped by `skip_decided` until a person decides again. This
   follows D3: a stale decision re-opens a question for a person, and a build does not answer it.
6. **A row the re-verdict sweep has not reached yet** is served as last judged. It can miss a
   bound that arrived since; the next sweep brings it up to date.

7. **A module-stream bound counts as a known fix, also for an install outside that stream**
   (found on the VM check below). Knowledge records every same-EL-major bound the install is
   below, and that includes builds of another module stream. Example: `python3-ply 3.9-9.el8`
   is "below" four `3.11-10.module+el8...` builds. A plain rebuild does not pick those up, so
   the request would be made, the build would run, and the comparison would show the Finding
   still open. On the checked Release 44 of 92 counted entries had only module-stream bounds.
   Knowledge's open reason already says "likely not reachable" for this shape, but the
   structured `verdict_behind` does not tell the two apart. Part 2 must not send an event
   before this is settled (backlog `KN-BEHIND-MODULE-1`).

**VM check, first run 2026-11-28** (task 3.5, main after #275, auth on, admin key; one Release).

- Knowledge answered for 640 live occurrences: 563 `known`, 44 `none`, 33 `unknown`.
- With no rebuild tag: `tags_applied` true, tag mode `off`, effective mode `off` set by `tag`,
  ceiling `ask`. Outcome `none`. Correct.
- The judgement looked at 596 open occurrences: 92 counted, 235 below the floor, 234 scope
  components, 33 fix unknown, 2 decided, 0 no fix. The sum is 596.
- One CVE gave 37 of the 92 counted entries (one flaw, many packages of one build).
- **Defect found: a tagged Release read as untagged.** `rebuild:ask` was set on the Release and
  the judgement still said tag mode `off`. Cause: the client read `tags` from Registry's
  single-entity views (`GET /releases/{id}` and the like), which the API schema lists but the
  handler never fills; only the list views and the tag reads carry tags. So the read broke the
  rule it states, "a tag list that could not be read never reads as no tag". The safe
  direction held (nothing could be asked for), but no Release could ever take part.
  **Fix:** the client reads each level's own tags from `GET /<kind>/{id}/tags`, and an answer
  without a `tags` field is an error. Registry follow-up: backlog `RG-VIEW-TAGS-1`.
- The tag steps (ask on the Release, off on the Product) are to be run again after the fix.

**VM check, second run 2026-11-28: PASSED** (task 3.5, main `27dffe3` with the tag fix; the same
Release). In order:

1. No rebuild tag: outcome `none`, mode `off`, set by `tag`.
2. `rebuild:ask` on the Release: outcome `recommend`, mode `ask`, tag level `release`, 92
   counted. Set by `installation`, because the tag and the installation policy both say `ask`
   and the policy side is named on a tie.
3. `rebuild:auto` on the Release: still `recommend`, mode `ask`, set by `installation`. The tag
   asked for `auto` and the installation's `ask` held (D17).
4. `rebuild:off` added on the Product, with `rebuild:auto` still on the Release: outcome `none`,
   mode `off`, set by `tag`, tag level `product`. Off on any level wins (D4).
5. Both tags removed: back to step 1.

Nothing was sent at any step. Not tried on the VM: a tag on the Project level, mode `auto` on
the installation (so `request` was not seen), and Knowledge switched off; the unit tests cover
all three. Part 1 is closed. The count of 92 still holds the module-stream entries of open
point 7.

**Open point 7 decided and built (owner, 2026-11-28).** The owner chose: a fix that exists only
in another module stream does **not** count for a rebuild, and is shown as its own group. The
other two choices were "count them like today" and "make it a policy field"; a field can still
be added later.

- **Knowledge.** `GET /releases/{id}/fix-verdicts` has a fourth `fix` value, `other_stream`: the
  occurrence is open and below vendor bounds, and none of them can be reached by a plain update.
  The rule is the structured form of the two shapes the open reason already states in prose:
  (a) the install and every bound are module builds and no bound shares the install's upstream
  series; (b) the install is a base-repository build and every bound is a module build. One
  reachable bound (a plain build, or a module build of the install's own series) keeps it
  `known`. The value is derived on read from the stored version and bounds, so there is no
  migration, no stored row changes and no `VerdictGeneration` bump.
- **Governance.** Under `fix_required` an `other_stream` occurrence is never targeted. When it
  is severe enough to count otherwise, it is listed in `other_stream` on
  `GET /releases/{id}/rebuild-evaluation` with the builds of the other stream, and counted under
  `skipped.fix_other_stream`. When it is below the floor it is counted under `below_floor`
  only. With `fix_required` off the stream does not matter. An older Governance reads the new
  value as `unknown`, which also does not count.
- **Not changed.** The fix-available alert (EDR-INCIDENT-01 D1) still announces such a bound.
  That is the rest of backlog `KN-BEHIND-MODULE-1`.

**VM check of this change (2026-11-28, task 4.0a): PASS.** Same Release as VM run 1 and 2, no
tag set, installation policy at its defaults.

| What | Before (#275) | After (#277) |
| --- | --- | --- |
| Fix answers `known` | 563 | 184 |
| Fix answers `other_stream` | not a value | 379 |
| Fix answers `none` / `unknown` | 44 / 33 | 44 / 33 |
| Considered | 596 | 596 |
| Counted (`targeted`) | 92 | 48 |
| Listed in `other_stream` | not a list | 44 |
| `skipped.fix_other_stream` | not a key | 44 |
| `skipped` below_floor / scope_component / fix_unknown / decided | 235 / 234 / 33 / 2 | same |
| Outcome | `none` (no tag) | `none` (no tag) |

- The 92 entries split into 48 and 44, as measured by hand in VM run 2.
- The groups still add up: 48 + 44 + 235 + 234 + 33 + 2 = 596.
- The first `other_stream` entry is a base-repository build of a Python library whose four
  bounds are all module builds of a newer series: shape (b) of the rule.
- **Observation, not a defect of the judgement.** Knowledge answers `other_stream` for 379 of
  the 563 occurrences that had a bound (67%). In the judgement only 44 of them surface, because
  the others are scope components or below the floor and are grouped there first. The share is
  higher than among the counted entries (48%), which fits: a module-stream advisory lists its
  whole rebuild set, and scope components come from exactly those advisories. It has not been
  sampled by hand yet; that is task 4.0b and backlog `KN-OTHER-STREAM-SAMPLE-1`.

**Hand sample of the `other_stream` answers (2026-11-28, task 4.0b).** The 379 answers belong to
39 different packages, so about ten CVEs each. The first 20 packages by purl were read with
their bounds:

- 20 of 20 are right. Each install is a base-repository build (`...el8`, two of them
  `...el8_10.1`) and every one of its two to five bounds is a module build
  (`...module+el8.x...`). That is shape (b) of the rule: no bound can be reached by a plain
  update.
- All 20 are Perl library packages, and the bounds are the builds of a newer Perl module
  stream. One module stream with many packages and many CVEs explains the high count.
- Limit of the sample: it is sorted by purl, so it shows one family. The other 19 packages
  have not been read.

## Honest limits

- **A rebuild fixes only what a rebuild can fix.** If the base image has no fixed package yet,
  `fix_required` holds the request back; if the fix needs a source change, the build runs and
  the comparison shows it still open.
- **`fix_available` is as good as the feeds.** Today the fix signal comes from the vendor feeds
  that are switched on. A language package with no feed fix never triggers.
- **The connector is outside Themis's guarantees.** Themis can prove what it asked for and what
  came back, not what the pipeline did in between.
- **"At most one build per intent" is a proof only with an idempotency key in the build
  system.** Without one the connector closes the paths it controls and sends the rest to a
  person (D39 item 7).
- **Two Communication nodes racing on one release** is closed by D13 for cycle creation. Two
  nodes may still both try to deliver one intent; the event id makes that harmless (D12).
- **Three policy levels are more to keep in order than one.** The list read of D11 is the
  control; a release-level policy should stay the exception.
- **Tags opt in, and tags are editable by a product key.** See D4 and D17.
- **An approval is as strong as the key and the name behind it.** See D22.

## What this record does NOT decide

- A schema for the build profile. It stays opaque until a second build system shows which keys
  are common.
- The pull transport of D1.
- A per-Release attempt limit (refused in M2-8, not reopened).
- Stopping a cycle that is already open when the mode is switched to `off` (D46 item 11).
  Today an open cycle runs to its end or its attempt limit.
- Deploying the rebuilt image. Themis asks for a build and checks the SBOM; rollout stays with
  the enterprise.
