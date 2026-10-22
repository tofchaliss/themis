# EDR-REMEDIATION-01 — Remediation policy: SLA, risk acceptance, upload outcomes, outbound webhooks, KEV detail, metrics, tags

Status: **ACCEPTED 2026-10-22 by the owner** (proposed and answered the same day; Q1–Q5 and the
safeguards S1–S3 are recorded in D8). Implementation is authorized in the order below, one PR per
decision. Nothing is implemented yet. Origin: the owner's pick
of ports 1, 2, 3, 4, 5, 7 and 8 from [`DEFECTDOJO-COMPARISON.md`](../DEFECTDOJO-COMPARISON.md)
(port 6, more intake dialects, is deferred "as we go on"). Every decision below is a domain-model,
API or schema change, so each needs the owner's approval before code (CLAUDE.md, "Must ask").

The ideas are DefectDojo's; the rules are Themis's. Four Themis rules bind every decision:

- **R-A. A Position is the only decision.** Nothing in this record creates, edits or retracts a
  Position. A deadline, a warning or a webhook can re-open a QUESTION; only a person (or a narrow
  policy that already exists) answers it.
- **R-B. Absence is not proof.** A component missing from a newer SBOM is reported, never treated as
  fixed or `not_affected` (EV-CURRENT-SBOM-1's gate).
- **R-C. Gathering Is Not Knowing, and the relevance bound holds** (EDR-KNOWLEDGE-01 D5). New feed
  facts are per-CVE, for carded CVEs only.
- **R-D. Outward channels have no inbound authority** (EDR-DELIVERY-01 D-N-7). Nothing that happens
  in Jira, Slack or a mail changes Themis state.

---

## D1 — SLA policy: days to fix per severity, a clock per Finding, breach re-surfaces

> **Realized 2026-10-22.** The clock is `domain.EvaluateSLA` (pure, 100% covered), reading the
> Finding's creation time, its frozen bucket, its whole Position history with review-by dates,
> the stale mark, the stage stop and CISA's due date — so nothing about the clock is stored and a
> policy change applies at the next read. Migration 000019 adds `findings.sla_bucket` (frozen by
> the first `SetBaseScore`, back-filled from the current score), `findings.stage_stopped_at`
> (first resolve/archive, cleared on reopen; NULL for older stops reads `not_applicable`, never a
> guess), `sla_policies` (scope `''` = estate) and `sla_breaches` (one row per Finding per period).
> States add `paused`, `met` and `missed` to the four above, so a stopped clock still says whether
> it stopped in time. The sweep runs on `THEMIS_REVIEW_BY_INTERVAL`; an unresolvable Product
> reads the estate policy. Named tests: `TestSLABreachNeverChangesGovernanceStateS1`,
> `TestSLAService_BreachWritesOnlyTheBreachLogS1`, `TestSLARestartNeverErasesElapsedTimeS2`, and
> the S1 half of `TestSLAStore`.

**Decision.** An SLA policy is a table of *days to fix* per severity bucket (Critical, High, Medium,
Low), each with an *enforce* switch. One estate-wide default policy; an optional override per
Product. Each Finding gets a derived **SLA due date** and a state: `within`, `due_soon` (inside a
warning window, default 7 days), `breached`, or `not_applicable`.

- **The clock starts when the Finding is created** (`findings.created_at`, already stored). Not when
  the CVE was published: Themis cannot be late for a flaw before it knew the release carried it.
- **The severity is the Finding's `base_score` bucket** (the M1b-5 ladder the tickets already use),
  read at Finding creation and **frozen on the Finding**. A later score change does not move the due
  date; it is shown as "severity changed since the clock started". Recommended because a moving
  deadline is a deadline nobody can plan against. *(Q1: answered, see D8.)*
- **A KEV CVE takes CISA's due date when that is earlier** (D5 supplies it).
- **The clock stops** when the Finding leaves the queue by a human decision: a `not_affected` or
  `mitigated` Position, or the Finding moving to the `resolved` or `archived` stage. It **pauses** under an
  unexpired `accepted_risk` or `deferred` Position and **restarts from zero** when that acceptance
  expires or is re-surfaced (`disposition_stale`). Recommended over "keeps running": an accepted risk
  is a decision with its own review date (D2), and a breach during it would double-count.
  *(Q2: answered, see D8.)*
- **A breach changes nothing.** It is a projection field on the Finding and the posture, plus an
  event `governance.sla_breached.v1` that Communication can deliver (D4). Never a Position, never a
  stage change (R-A).

**Where.** Governance: policy table + migration, a pure `domain.SLAClock` function, a read
projection beside `residual_priority`, a sweep on the existing review-by timer that emits the breach
event once per Finding. API: `sla {due, state, days_left}` on Finding and posture; `GET/PUT
/sla-policy` (admin scope). Dashboard: a due column and a breached filter.

**AI angle.** None needed; this is arithmetic. Later, the AI explanation can say "breached 4 days
ago, fix published in X" when it already explains a Finding.

**From DefectDojo:** `SLA_Configuration` (days + enforce per severity, per product) and
`sla_start_date`. **Not taken:** DefectDojo's clock running on severity edits, and its
`restart_sla_on_reactivation` semantics, which presume flag flips Themis does not have.

## D2 — Risk acceptance: owner, treatment, proof, and a warning before the review date

> **Realized 2026-10-22.** `domain.AcceptanceTerms` rides `Finding.AcceptProposalWith`; the terms
> land on `PositionInputs` (immutable with the version). Q3 is enforced in the domain:
> `ErrOwnerRequired` for a human accepting `accepted_risk` with no owner; policy and system
> accepts are not asked. Owner, treatment or proof on any other stance is refused
> (`ErrTermsNotApplicable`). The warning runs on the review-by timer: current Positions
> (accepted_risk, deferred, not_affected) whose review date falls in the next
> `THEMIS_REVIEW_WARNING` (default 336h), not yet warned for that version, get one
> `governance.review_due_soon.v1` carrying the owner; the `review_warnings` table makes it
> once-only and the Finding is never written. The mail to the owner is not built here: the
> event is on the bus for D4's webhook, and a Communication mail is a recorded follow-up. The
> AI angle (suggesting a treatment) is not built.

**Decision.** An `accepted_risk` or `deferred` Position gains three optional, structured inputs
beside the existing `review_by`:

- **owner**: the accountable person, a free-text identity (an email or name), distinct from the
  decider (who accepted it) because they are often different people.
- **treatment**: `accept` · `transfer` · `avoid` · `mitigate_later` (closed set). `transfer` is the
  REP-2 "Transferred" state; `mitigate_later` covers "Mitigate in future release".
- **proof**: a reference (URL or document id) to the justification artefact. Stored as text, never
  fetched.

And a **review warning**: `review_by` minus a window (default 14 days) emits
`governance.review_due_soon.v1` once per Position version; Communication mails the owner's audience
(D4 can also carry it). Expiry keeps today's behaviour (RF-2: `disposition_stale`, residual equals
effective).

- **Append-only holds** (R-A): changing the owner or the treatment is a new Position version with the
  same stance, recorded against the person who changed it.
- **No "expire silently"**: DefectDojo's `reactivate_expired=false` is not offered. An expired
  acceptance always comes back to the queue.
- **Required when?** Recommended: `owner` is **required** for a new `accepted_risk` Position from a
  person; optional for policy and vendor-raised proposals until signed. *(Q3: answered, see D8.)*

**Where.** Governance `PositionInputs` + migration; decision API body fields; dashboard decision
form; the warning on the existing review-by sweep.

**AI angle.** `recommend_position` may suggest a treatment; it may never fill the owner.

## D3 — Upload outcome: what one SBOM changed, in four buckets

**Decision.** For each new SBOM evaluated on a Release, Governance computes, against the
immediately-previous SBOM of the same Release (the N-M2e baseline rule):

| Bucket | Meaning |
| --- | --- |
| `new` | a Finding that did not exist on the Release before this SBOM |
| `reappeared` | a Finding whose components were absent from the previous SBOM and present again |
| `no_longer_present` | an open Finding none of whose active components is in this SBOM |
| `unchanged` | an open Finding still present |

The counts and the CVE lists are stored with the release-evaluated event (an additive field on
`governance.release_evaluated.v1` and in `release_evaluated_events.body`), shown on the posture page
and in the evaluation mail and ticket ("3 no longer present in this build").

- **`no_longer_present` is a report, not a state** (R-B). The Finding stays open with its Position.
  What should eventually happen to such a Finding is EV-CURRENT-SBOM-1's design, and this bucket is
  the input it needs. Measured 2026-10-19: 1 such Finding on the estate today.
- **`reappeared` re-opens nothing by itself**; a Finding that was resolved and re-observed already
  follows the lifecycle's own re-open rule.
- The intake receipt does **not** carry the buckets (the intake answers before correlation); it
  carries a link to the evaluation event instead.

**Where.** Governance release-evaluation worker (it already has the release and the SBOM); Evidence
listing by release for the baseline. No new table.

## D4 — Outbound webhook channel, one-way, with recorded health

**Decision.** A delivery intent kind `webhook`: an HTTPS POST of a small JSON document to a
configured URL per governed *audience name*, so Slack and Teams incoming webhooks work without a
sender per product. Events it may carry, each opt-in by configuration: release evaluated, SLA
breached (a **daily digest per Product**, not one message per Finding), review due soon, disposition
stale, rebuild loop exhausted.

- **Health is recorded** per destination, DefectDojo's four states: `active`, `active_tmp`
  (a transient failure, retrying), `inactive_tmp` (paused after repeated failures, retried later),
  `inactive_permanent` (an operator must re-enable). Shown on the Feeds page beside feed health.
- **The existing intent machinery applies unchanged**: materialized payload at enqueue, retries,
  dead letter, `deliveryctl`. HTTPS enforced at configure time, loopback excepted, like Jira and
  Jenkins. Secrets (a signing key, if the receiver supports one) from the environment only.
- **One-way** (R-D): the webhook has no callback route.
- **Payload shape**: a stable Themis schema (`event`, `product`, `project`, `release`, `summary`,
  `link`), plus an optional Slack/Teams text field so the message renders without a relay.
  Recommended over raw event bodies, which would make every internal field a public contract.

**Where.** Communication: `IntentWebhook`, a sender in `adapters/delivery/`, a CHECK-constraint
migration, `THEMIS_COMMUNICATION_WEBHOOK_TARGETS` (audience=url pairs, secrets by reference).

## D5 — KEV detail: date added, due date, ransomware use

> **Realized 2026-10-22.** Knowledge parses `dateAdded`, `dueDate` and
> `knownRansomwareCampaignUse` (`Known` only) into the exploit signal; reconciliation takes the
> earliest stated dates and ORs the flag; the card and `FaultlineEnriched` carry them (omitted
> when not stated). Governance migration 000018 stores `signal_kev_due`, `signal_kev_ransomware`
> and `decided_kev_ransomware`; `DispositionDrift.RansomwareBecameKnown` re-surfaces through the
> watcher (S3). The due date is not a drift premise.

**Decision.** The exploit signal carries three more KEV facts from the same CISA catalogue Themis
already reads: `kev_added` (date), `kev_due` (date) and `kev_ransomware` (`known` / `unknown`).

- **Additive** on the Knowledge exploit-signal Proposal and on `FaultlineEnriched`; the reconciled
  view exposes them on the card.
- **`kev_due` feeds D1** (the earlier of the SLA due date and CISA's due date).
- **"Ransomware use became known" is a new drift reason** for the disposition watcher: an accepted
  risk resting on "exploited but not by ransomware crews" re-surfaces when that changes.
  One-directional, like the existing drift rules: a change toward safer never re-surfaces.
- **Relevance bound holds** (R-C): only carded CVEs, exactly as today.

**Where.** Knowledge `adapters/feed/epsskev*.go` + `domain.ExploitSignal`; Governance
`ExploitSignals` + the watcher. No new feed, no new outbound call.

## D6 — Estate remediation metrics as a Publication

**Decision.** A Communication report, `remediation-metrics`, materialized on request (and later on a
schedule through D4), per Product and estate-wide:

- **open Findings by age band** (0–7, 8–30, 31–90, over 90 days since creation), split by severity;
- **share within SLA** (from D1) and **breached now**;
- **mean time to decision** (Finding creation to first human Position);
- **mean time to remediation**, defined as Finding creation to the first evaluated SBOM in which it
  is `no_longer_present` *and* a person has since resolved or decided it — so the metric never counts
  absence alone as a fix (R-B). Recommended; the honest alternative, "until a person resolved it", is
  shown beside it. *(Q4: answered, see D8.)*

Rendered as a Publication (JSON + markdown), like the existing reports, and as a dashboard page. It
is the first concrete piece of REP-1; the other REP-1 reports keep their own grill.

**Where.** Governance read projection for the numbers (one query per Product, not per Finding);
Communication serializer; dashboard "Reports" page.

## D7 — Tags on Product, Project and Release

**Decision.** Registry stores a small set of free-form tags per Product, Project and Release
(`team:payments`, `env:prod`, `customer-facing`), editable by an admin or the product's own key.
They are **filters only**: on the estate page, What's new, the metrics (D6) and webhook routing (D4,
"send breaches for `team:payments` to this audience").

- **Tags never weight priority.** Priority stays `base_score × blast-multiplier`; a tag that changed
  ranking would be an unreviewed policy.
- **No tags on Findings** in this record: a Finding's labels are its Position and stance.
- Inheritance: a Release shows its Project's and Product's tags; filters match on the union.

**Where.** Registry migration (one `tags` table keyed by entity), API on the three entities, a filter
parameter on the reads that list them.

---

## D8 — The owner's answers (2026-10-22) and two explicit safeguards

**Q1 — severity changes later: keep the original due date.** The severity bucket is frozen when the
Finding is created. A later change is shown, with a flag that it differs from the bucket the deadline
was computed from. The deadline is never silently reset.

**Q2 — during an accepted risk: pause, then restart from zero.** The SLA clock pauses while an
`accepted_risk` or `deferred` Position remains valid. When it expires or becomes stale and the
Finding returns to the queue, a new SLA period starts. The Finding's creation time and the
acceptance history are retained (see S2).

**Q3 — owner on accepted risk: required for human acceptance.** A person creating an `accepted_risk`
Position must name an accountable owner, kept distinct from the decider. A policy- or vendor-raised
proposal may omit the owner until a person accepts it, and accepting it then requires one.

**Q4 — what counts as remediated: evidence plus a human decision.** Disappearing from an evaluated
SBOM is not proof of a fix. The primary remediation metric requires both that the Finding is no
longer present in an evaluated SBOM and that a person subsequently resolved or decided it. Time to
human resolution is reported as a separate measure, labelled so the two cannot be confused.

**Q5 — default days to fix: all four enforced.**

| Severity | Default SLA |
| --- | --- |
| Critical | 7 days |
| High | 30 days |
| Medium | 90 days |
| Low | 180 days |

The earlier deadline wins when a CISA KEV due date applies. These are initial defaults: one
estate-wide policy with optional per-Product overrides.

**S1 — an SLA breach never changes governance state.** A breach may update a derived status, emit an
event, appear in reports and trigger notifications. It must not mark a Finding affected, accept a
risk, change a stage, or create, edit or retract a Position. This is R-A applied to D1, stated so a
test can hold it: the breach path writes no Finding aggregate field other than the derived SLA
projection.

**S2 — restarting the SLA never erases elapsed time.** The active clock may restart after an
acceptance expires, but the record keeps the original Finding creation time and every period spent
under acceptance (start, end, Position version). Metrics (D6) report the Finding's total age from
creation and its total time under acceptance beside the current SLA period, so a long-running risk
is never understated.

**S3 — ransomware re-surfacing follows the existing path.** An accepted risk that becomes stale because
ransomware use becomes known (D5) is re-surfaced by the disposition watcher, which records
`disposition_stale {since, reason}` on the Finding exactly like the KEV and EPSS drifts (RF-2). A
notification of it (D4, mail) is a consequence of that state, never a substitute for it.

## Order of work, once approved

D5 (small, feeds D1) → D1 → D2 → D3 → D4 → D6 → D7, agreed by the owner. Each lands alone in its own
PR with focused tests, the coverage tiers, a reversible migration verified up and down, and a VM
check recorded in the backlog. S1, S2 and S3 each get a named test in the PR that implements the
decision they constrain.

## What was considered and not adopted

- DefectDojo's **auto-close on reimport** and **do-not-reactivate**: break R-B and R-A.
- **Jira status driving Themis state**: breaks R-D.
- **Status flags** (verified, false positive, out of scope) as independent switches: Themis records
  one stance per Position with its rationale, which is what an auditor reads.
- **Retroactive false-positive history**: applying one decision to every similar Finding silently is
  what roll-forward deliberately refuses (EDR-ROLLFORWARD-01: it proposes, never copies).
