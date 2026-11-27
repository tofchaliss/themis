# EDR-REBUILD-01 — A policy decides the image rebuild, a signed event carries it, a build connector starts it

Status: **PROPOSED — 2026-11-26.** Design only, no code. The owner picked the form factor the
same day (choice 1 below: signed event plus build connector). Choices 2 to 5 carry an assumed pick
and wait for the owner. Feature work stays behind the release freeze: each step needs the owner's
go.
**Revision 2, 2026-11-26:** the owner chose to keep the build configuration in Themis, as a build
profile per Project and Release (D10). D10 replaces the mapping part of D8.
**Revision 3, 2026-11-27:** after an outside review the owner chose a policy per installation,
Product and Release (D11). Five clarifications from that review are decided as D12 to D16. A
second review the same day gave D17 to D21; the owner decided that the policy is the ceiling for
automation and a tag can only restrict it (D17).
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
request, ever. A release-level tag `rebuild:off` wins over an inherited one.

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
    "cycle_id": "<n>", "attempt": 1, "max_attempts": 2,
    "reason": "fix_available",
    "policy_version": "<n>", "policy_scope": "product",
    "build_profile_revision": "<n>", "build_profile_scope": "project",
    "build_profile_sha256": "<hex>",
    "targeted": [ { "finding_id": "<uuid>", "cve": "CVE-0000-0000", "purl": "<purl>",
                    "current_version": "<version>", "fixed_version": "<version>",
                    "fix_source": "<feed>" } ],
    "build": { }
  }
}
```

- `build` is the release's build profile, copied as stored (D10, revision 2).
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

The connector is small: verify the signature, look up the release in a mapping file, start the
pipeline, nothing else. It holds the CI credentials and the mapping. It keeps no security state.

- It lives in its own repository so that an enterprise can fork or replace it without touching
  Themis.
- A reference connector covers the generic cases (a parameterized job, a pipeline trigger API,
  a repository dispatch).
- A CI system that can verify an HMAC webhook itself needs no connector at all.
- The mapping is keyed on product and project **names** and on tags, with a default entry, so a
  new release needs no new mapping line.

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

A Jenkins job with a webhook trigger reads `data.build.parameters` as its job parameters and the
other `data` fields as facts. The same block serves any other build system; only its keys
differ.

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

1. The connector keeps a durable record per event id and writes it **before** it calls the
   build system.
2. An event id already recorded as started is acknowledged and starts nothing.
3. An event id recorded but with an unknown outcome (a crash between the call and the record)
   is **not** sent again blindly. The connector first asks the build system for a build that
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

Governance does not publish the same request twice either: a request is keyed on the release,
the policy scope and version, and the targeted set.

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
2. The approval records the **actor, the time, the cycle** and those frozen facts. The request
   that follows carries exactly them.
3. A policy or profile change after the recommendation does not alter it. The next cycle uses
   the new values.
4. A recommendation nobody answered **expires after 7 days**. It is evaluated afresh at the
   next trigger.
5. Only a person may approve: `admin` or the Product's own key. The AI cannot.

### D16 — The request names the build profile it used (revision 3)

The event carries `build_profile_revision`, `build_profile_scope` (`project` or `release`) and
`build_profile_sha256` (over the stored bytes) beside `policy_version` and `policy_scope`, and
the `cycle_id` that ties all attempts and callbacks together. Each targeted entry names its
Finding. Positions are append-only, so the assessment behind each Finding at request time can
be read back from the request's timestamp. With the intent id, these fields answer "which policy
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

The effective-policy read of D11 item 3 returns the effective mode and which of the three
values set it.

### D18 — The connector must authorize the job; the signature is not enough (revision 3)

The signature proves that the event came from Themis. It does not prove that the job named in
`build` is allowed for that Product. These checks are a **required** part of the connector
contract, and the reference connector refuses to start without them configured:

1. An allow-list of jobs, **per Product and Project**. A job not listed for the event's
   Product and Project is refused.
2. An allow-list of parameter **names** per job. An unknown name is refused, not dropped.
3. Value checks per parameter (type, length, a pattern), so a value cannot carry shell or
   pipeline syntax.
4. A build-system credential that can start only the listed jobs.
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
2. The release's version of the component is below that fixed version.
3. The component is a carrier, or its claim class is unknown (`carrier_only`, D2).

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
| refusals | answers "not started" from the connector (freeze window, job not allowed, D18) | 3 per cycle |
| attempts | builds that were accepted | `THEMIS_COMMUNICATION_REBUILD_MAX_ATTEMPTS` (2) |

1. The attempt is counted when the request is delivered. A refusal callback **gives it back**.
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

## Choices for the owner

| # | Choice | Assumed pick | State |
| --- | --- | --- | --- |
| 1 | Form factor | signed event plus build connector | **answered 2026-11-26** |
| 2 | Policy language | fixed fields (D2) | open |
| 3 | Where the policy is stored | Governance database with API and audit (D9) | open |
| 4 | Default mode | `ask` (D5) | open |
| 5 | Where the connector lives | its own repository (D8) | open |
| 6 | Where the build configuration lives | in Themis, per Project and Release (D10) | **answered 2026-11-26** |
| 7 | Policy scope | installation, Product and Release, nearest wins as a whole (D11) | **answered 2026-11-27** |
| 8 | Mode: policy against tag | the installation policy is the ceiling, a tag only restricts (D17) | **answered 2026-11-27** |

## Order of work (proposed; each step alone, on the owner's go)

| Step | What | Touches |
| --- | --- | --- |
| R0 | this record and the backlog item | docs |
| R1 | policy record, evaluation in the domain, read and write API | Governance domain, API, migration |
| R1a | Product and Release policy overrides; the effective-policy read and the list read (D11) | Governance domain, API, migration; GUI |
| R2 | evaluation on `new_sbom` and on `fix_available`; the two new events; tag scope | Governance, Registry read seam |
| R2a | build profile on Project and Release: storage, history, read and write API, the secret-name and size checks, a GUI form | Registry domain, API, migration; GUI |
| R3 | Communication consumes the events; the cycle opens from them; `rebuild_requested` and `rebuild_recommended` webhook routes; signed-only rule | Communication |
| R4 | mode `ask`: the "start rebuild" action in API and GUI | Governance or Communication API, GUI |
| R5 | reference build connector, with the durable event record of D12 and the required checks of D18 | new repository |
| R6 | VM check: one release tagged, one fix published, one build, one comparison | test VM |

R1 changes the domain model and an API, R3 changes event contracts, R5 is a new repository. Each
is on the "must ask" list.

## Honest limits

- **A rebuild fixes only what a rebuild can fix.** If the base image has no fixed package yet,
  `fix_required` holds the request back; if the fix needs a source change, the build runs and
  the comparison shows it still open.
- **`fix_available` is as good as the feeds.** Today the fix signal comes from the vendor feeds
  that are switched on. A language package with no feed fix never triggers.
- **The connector is outside Themis's guarantees.** Themis can prove what it asked for and what
  came back, not what the pipeline did in between.
- **Two Communication nodes racing on one release** is closed by D13 for cycle creation. Two
  nodes may still both try to deliver one intent; the event id makes that harmless (D12).
- **Three policy levels are more to keep in order than one.** The list read of D11 is the
  control; a release-level policy should stay the exception.
- **Tags opt in, and tags are editable by a product key.** See D4.

## What this record does NOT decide

- A schema for the build profile. It stays opaque until a second build system shows which keys
  are common.
- The pull transport of D1.
- A per-Release attempt limit (refused in M2-8, not reopened).
- Deploying the rebuilt image. Themis asks for a build and checks the SBOM; rollout stays with
  the enterprise.
