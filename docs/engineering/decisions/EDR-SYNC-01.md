# EDR-SYNC-01 — One decision, chosen scope: a CVE assessment applied across the projects of a product

Status: **ACCEPTED — 2026-11-03 (owner merged PR #222; "go s1" the same day). S1 built 2026-11-03, see Realization notes.**
Date: 2026-11-03
Author: the design discussion of 2026-11-03 (thread "Nessus report intake"); owner picked
"scope at decision time" over "auto copy" and "proposals only" the same day.

## Purpose

Engineering Decision Record for **how one person's assessment of a CVE reaches the other projects
of the same product that carry the same CVE in the same component**. The owner's case: product
A product has several projects (one per deliverable) built from the same base, each with a release of
the same version. A person decides `CVE-2026-111497` on project A's release; project B's release
of the same version holds the same CVE in the same package and today shows it undecided. The
owner wants it updated "automatically, soft-realtime" — minutes, not seconds, and without a
second person repeating the same click per project.

## What Themis does today (measured 2026-11-03, code at `acbd710`, after v0.5.0)

1. **A Position is per Finding, a Finding is per (release, CVE).** Nothing links the Findings of
   one CVE across releases except the Faultline id they share (`FindingsByFaultline`).
2. **Roll-forward (EDR-ROLLFORWARD-01) covers one direction only.** A judged Position on a
   release of project P raises a system PROPOSAL (Inferred, never auto-acceptable) on an undecided
   Finding of another release **of the same project** P, at artifact or component level. Across
   projects it raises nothing, by design: D1 says a project is the line of releases that succeed
   one another, and its "Not decided here" defers a different product explicitly. A different
   **project of the same product** is the gap between those two lines, and this record fills it.
3. **The AI road sees across products**, as precedent for `recommend_position`, with a model in
   the path and a person deciding (EDR-INTELLIGENCE-01 C6). It is a suggestion, not a sync.
4. **The authority line has one automatic decider** (EDR-GOVERNANCE-01 D15: a system
   `not_affected` on Observed evidence, policy-accepted). Every other Position is a person's act
   recorded against that person (`key:<id>` under auth, EDR-SECURITY-01 D10).

So the owner's wish, read as "copy the Position", collides with (4): a Position would appear on a
Finding no person looked at, recorded against someone who never saw it. Read instead as **"let me
decide once for the whole product"**, it fits the line exactly — the subject of the decision gets
wider, the decider stays a person. That is the reading this record adopts.

## Decisions

### D1 — Scope is a property of the decision, chosen by the decider

A decision (accept of a proposal, which is how every human Position is established) carries a
**scope** ∈ `release` | `project` | `product`:

| scope | the decision applies to |
| --- | --- |
| `release` | this Finding only — today's behaviour, and the API default |
| `project` | every Finding of the same Faultline on any release of the same project, matching per D2 |
| `product` | every Finding of the same Faultline on any release of any project of the same product, matching per D2 |

`DecisionRequest` gains `scope` (optional, default `release`); the dashboard's decision form
gains the picker, pre-selected from `THEMIS_GOVERNANCE_DEFAULT_DECISION_SCOPE` (default
`release`; the owner's estate sets `product`, so the one-click case needs no extra click). The
scope is recorded as a **PositionInput** — the decision rested on it — beside `ReviewBy`,
`Owner`, `Treatment` and `Proof`, and is shown wherever the Position is shown ("decided by
<person> for product <product>").

### D2 — "The same" means the same CVE in the same component; a different component is never synced

A target Finding qualifies when it shares the Faultline **and** `RollForwardEligibility(target,
source)` over the two Findings' active carrier components returns `artifact` or `component`
(EDR-ROLLFORWARD-01 D3: same purls, or the same packages with versions moved). The
**vulnerability** level — the CVE is shared but the components differ, or the target has no
carrier — is never applied: a decision about `openssl` says nothing about `kernel`, whatever the
scope. Such a target gets the roll-forward PROPOSAL instead (D6), so the person sees that a
scoped decision exists and why it did not apply.

### D3 — Application establishes a real Position on each target, recorded against the person

For each qualifying target Governance establishes a Position with the **same actor** (the person
who decided), the same stance, the same `ReviewBy` / `Owner` / `Treatment` / `Proof`, a
rationale that is the original rationale verbatim plus one line naming the source ("applied by
scope `product`, from release <version> of project <name>, Position v<n>"), and
`PropagatedFrom {FindingID, PositionVersion}` as a PositionInput. `DecidedWith` is the target's
**own** exploit signals at application time, so the disposition watcher (GOV-14b) asks its
question per Finding, as today. The Position rides the normal `position_established` /
`position_revised` events, so Jira, mail, the SLA clock (EDR-REMEDIATION-01 D1: an accepted risk
pauses it) and `residual_priority` behave exactly as for a hand-made Position. Nothing new is
invented downstream; the only new fact is that one click produced N Positions, and each says so.

The proposal the target's Position accepts is raised by Themis with proposer **the person**
(`human`, the decider's actor), id `scoped:<source finding>:<target finding>:<source version>`
(deterministic: a re-run establishes nothing twice). It is not a system proposal — the person
made this claim, for this scope — which is why no trust check stands in its way and why the
audit reads true.

### D4 — It runs soft-realtime, off the request path, and keeps applying to Findings born later

The accept request records the Position and its scope and returns. Propagation runs on the
**release-evaluation worker** (EDR-ROLLFORWARD-01 D5 — the Registry hop product → projects →
releases must not sit on the inbox transaction) and on a small **scope sweep**
(`THEMIS_SCOPE_SWEEP_INTERVAL`, default `1m`, `0` off) that drains `scoped_decisions` rows —
one per scoped decision, marked `applied_at` once every current target was visited. Minutes, as
the owner asked. The same two hooks handle the second half of the wish: a Finding that opens
**later** (a new upload in another project of the product) is matched against the standing scoped
decisions of its Faultline when its release is evaluated, and gets its Position then.

### D5 — Precedence: a local decision wins; a propagated one follows its source

- A target whose current Position a person established **directly** (scope `release`, or a
  scoped decision of its own) is never overwritten by propagation from elsewhere.
- A target whose current Position was **propagated** from source S follows S: when S is
  re-decided with a scope that still covers the target, the target gets the new version (that is
  the "sync" the owner described); when S is re-decided with scope `release`, the target keeps
  its last propagated Position and is flagged `scope_withdrawn` for review — a decision, once
  made, does not vanish because its scope was narrowed (same rule as GOV-14b: it expires, it does
  not disappear).
- Two standing scoped decisions of the same Faultline that cover the same undecided target with
  **different stances** apply nothing; the target gets both as proposals and the pair is flagged
  `scope_conflict` on the dashboard. Themis never picks between two people.

### D6 — Roll-forward is unchanged and remains the fallback

EDR-ROLLFORWARD-01 keeps raising its same-project proposal where no scoped decision applies
(scope `release` decisions, vulnerability-level targets, conflicts). Its D1 "different product
never" stands unchanged: scope `product` is the widest this record allows, and a decision on one
product still says nothing about another.

### D7 — The GUI tells the truth before and after the click

Before: the decision form shows the scope picker and, beside it, the **preview count** from
`GET /findings/{id}/scope-targets?scope=` — "will also apply to 7 Findings in 3 projects", with
the list on demand — so the person knows what they are signing. After: the Finding page shows
"decided by <person> for product <product>" and, on a propagated target, "applied from release
<version> of project <name>" with the link. Vulnerability-level siblings show the roll-forward
proposal with the reason "component differs".

### D8 — Limits stated

The release and project names come from Registry; when Registry is unreachable the propagation
defers and retries (the row stays pending, the sweep logs it), it never guesses. A scoped
decision applies to Findings **in Governance**: a release whose correlation has not run yet has no
Findings and is picked up at its evaluation (D4). Scope is per decision, never per person or per
product permanently — a default is a pre-selection, not a policy.

## Order of work (proposed)

| Step | Scope | Touches |
| --- | --- | --- |
| **S1** | `scope` on `DecisionRequest` + PositionInputs (`Scope`, `PropagatedFrom`), `scoped_decisions` table, worker hook + sweep (D1–D4), `scoped:` proposal id, API `GET /findings/{id}/scope-targets`, env docs | Governance domain/app/adapters/store/http, `api/governance.openapi.yaml`, `node.env.example` |
| **S2** | GUI: scope picker with default, preview count, "decided for product" and "applied from" lines (D7) | `cmd/dashboard/static/app.js` |
| **S3** | Re-decision follow + `scope_withdrawn` + `scope_conflict` (D5), dashboard flags | Governance app/store, GUI |

Each step: OpenSpec change `phase3-decision-scope-<step>`, `make check-ci` green, VM-verified
with the owner's own case (two projects of one product, same version, same CVE: decide once with
scope `product` on A → B shows the Position within a sweep, recorded against the same person,
with the "applied from" line; a third project's later upload gets it at evaluation). Beta-period
change: each step ships only on the owner's explicit go.

## Realization notes

### Step S1 (2026-11-03) — scope on the decision, propagation, preview

- **The Position row is the queue**, not a `scoped_decisions` table: `finding_positions` gained
  `scope`, `propagated_from_finding`, `propagated_from_version`, `scope_applied_at` (governance
  migration 000023). A scoped Position with `scope_applied_at IS NULL` is pending; the sweep
  (`THEMIS_SCOPE_SWEEP_INTERVAL`, 1m) marks it after one successful pass and any failure leaves
  it pending. Written in the accept's own transaction, so a decision and its queue entry cannot
  disagree. A propagated Position is **born applied** — D6's "never a source" is structural.
- `release` scope is stored as `""`, so every pre-record Position reads back as release-scoped
  with no data migration.
- Propagation is an ordinary accept in the person's name: proposal
  `scoped:<target>:<source>:v<n>` (Asserted — the person's claim, not a rule's), accepted at
  once with the source's terms (review_by, owner, treatment, proof) and `PropagatedFrom`. The
  usual notes fire, so Communication and the SLA clocks see it like any decision.
- Two roads, one target rule: the sweep walks the source Faultline's siblings
  (`ScopePropagation.Targets`, shared with `GET /findings/{id}/scope-targets`); the
  release-evaluation worker walks a new release's undecided Findings looking for a standing
  scoped source, **before** roll-forward so roll-forward sees them decided. Disagreeing standing
  sources apply nothing and are counted (`conflicts` in the sweep report); the D5
  `scope_conflict` flag on the Finding is S3.
- No Registry seam ⇒ no scope: the node logs it at startup and the preview answers 503.
- **Names, not UUIDs** (owner, first VM round 2026-11-03): the Registry hop scope uses
  (`ReleaseOwnerResolver`) returns the product and project NAMES and the release version beside
  the ids. The ids decide scope; the names go into the propagated rationale ("applied by scope
  product from <project> <version> (Finding …)") and onto every preview target. A blank name falls
  back to the id, never to nothing.
- VM round 2026-11-03 (S1 PASS): decided once on project A with scope `product`; the one
  undecided sibling (a third project, artifact level) carried the Position within a minute,
  same person, `propagated_from` set; the sibling the owner had decided the day before kept its
  own Position (D5) — the owner read that as correct. A test stance was then corrected by hand
  on both Findings, because a re-decision does not yet follow (S3).
- Still open after S1: S3 (re-decision follow, `scope_withdrawn`, `scope_conflict` flags).

### Step S2 (2026-11-03) — the GUI tells the truth before and after the click (D7)

- Decide form: a Scope picker, default `release` (today's behaviour, nothing new to click).
  Choosing `project` or `product` fetches the preview from the same endpoint the sweep's
  target list comes from and says "Will also apply to N findings in M projects", each target
  as `<project> <version>` (level on hover); "reaches no other finding right now" when every
  sibling is decided or absent; a Registry outage or a node without the seam shows as an
  error, never as zero (D2's "nobody" vs "cannot tell").
- The accept carries `scope`; the toast says the decision was taken for the whole product or
  project and that siblings follow within a minute.
- After the click: the Current position line shows "decided for product/project" on the source
  and "applied from another release" on a propagated target (the rationale, shown with the
  proposal, names the source project and version); a `scoped:` proposal carries the chip
  "applied by scope", a `rollforward:` proposal "roll-forward". No link to the source Finding
  yet: the drawer opens from a posture row, and a cross-release jump is a later GUI step.
- Nothing in the GUI decides: the picker widens the subject of the person's own decision.

## What this record does NOT decide

- Any automatic decision. Scope widens the subject of a person's decision; it adds no decider.
- Syncing across **products**. EDR-ROLLFORWARD-01 "Not decided here" still holds.
- Syncing proposals, commissions or AI recommendations. Only an established Position has a scope.
- Replacing roll-forward's proposal with an auto-apply for scope `release`. That is a different
  question (the owner's "auto copy" option), declined 2026-11-03.
