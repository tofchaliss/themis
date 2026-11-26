# EDR-REBUILD-01 — A policy decides the image rebuild, a signed event carries it, a build connector starts it

Status: **PROPOSED — 2026-11-26.** Design only, no code. The owner picked the form factor the
same day (choice 1 below: signed event plus build connector). Choices 2 to 5 carry an assumed pick
and wait for the owner. Feature work stays behind the release freeze: each step needs the owner's
go.
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
    "attempt": 1, "max_attempts": 2,
    "reason": "fix_available",
    "policy_version": "<n>",
    "targeted": [ { "cve": "CVE-0000-0000", "package": "<name>", "fixed_version": "<version>" } ]
  }
}
```

- The signature is the existing `X-Themis-Signature: sha256=<hex>` over the body. A
  `rebuild_requested` route **without** a signing secret is refused at configure time: an
  unsigned request to build is not sent.
- Targets are `https` only, as for every webhook.
- The event is a request, not a command. The connector may refuse (freeze window, missing
  mapping); it reports that through the callback as a failed attempt.

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

A policy per Product is the expected next step and is not designed here.

## Choices for the owner

| # | Choice | Assumed pick | State |
| --- | --- | --- | --- |
| 1 | Form factor | signed event plus build connector | **answered 2026-11-26** |
| 2 | Policy language | fixed fields (D2) | open |
| 3 | Where the policy is stored | Governance database with API and audit (D9) | open |
| 4 | Default mode | `ask` (D5) | open |
| 5 | Where the connector lives | its own repository (D8) | open |

## Order of work (proposed; each step alone, on the owner's go)

| Step | What | Touches |
| --- | --- | --- |
| R0 | this record and the backlog item | docs |
| R1 | policy record, evaluation in the domain, read and write API | Governance domain, API, migration |
| R2 | evaluation on `new_sbom` and on `fix_available`; the two new events; tag scope | Governance, Registry read seam |
| R3 | Communication consumes the events; the cycle opens from them; `rebuild_requested` and `rebuild_recommended` webhook routes; signed-only rule | Communication |
| R4 | mode `ask`: the "start rebuild" action in API and GUI | Governance or Communication API, GUI |
| R5 | reference build connector | new repository |
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
- **Two Communication nodes still race** on one release (EDR-DELIVERY-01 honest limits). The
  cool-down narrows it and does not close it.
- **Tags opt in, and tags are editable by a product key.** See D4.

## What this record does NOT decide

- A per-Product or per-Release policy.
- The pull transport of D1.
- A per-Release attempt limit (refused in M2-8, not reopened).
- Deploying the rebuilt image. Themis asks for a build and checks the SBOM; rollout stays with
  the enterprise.
