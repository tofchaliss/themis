# EDR-ROLLFORWARD-01 — Same-CVE roll-forward as a deterministic Governance proposal

Status: **Accepted — 2026-10-16, from the Phase 1 audit "Auto-assessment and roll-forward" (B1/B2)**
Date: 2026-10-16
Author: the roll-forward investigation (AUTO-ASSESSMENT-ROLL-FORWARD-INVESTIGATION.md, Phase 2)

## Purpose

Engineering Decision Record for **what Themis does when a CVE that was already decided on one
release of a project turns up on another release of the same project** — the behaviour the
investigation calls roll-forward, and the one VAMS does by copying the assessment.

The Phase 1 audit found that the only cross-release reuse Themis had was the AI sweep: semantic,
budget-gated, off unless a token pool is set, and its same-CVE road was dead code (AI-RF-1, fixed
2026-10-14). There was no deterministic, model-free road at all. This record adds it, and settles
the granularity question the audit deferred (which VAMS level may propose).

## The authority line is unchanged

Nothing here decides. The pipeline already has exactly one automatic decider (EDR-GOVERNANCE-01
D15: a system `not_affected` on Observed evidence, auto-accepted by policy), and this record adds
no second one. Roll-forward **proposes**; a person accepts or rejects. The audit's safety fixture
(CVE-2026-33006: a scope-only Finding on the target release, a decided Finding elsewhere, expected
outcome no automatic Position) is the first test of the implementation and stays green.

## Decisions

### D1 — Roll-forward is a system Proposal carried from a sibling release of the same project, never a Position copied

When a Finding on (release R, Faultline F) has no Position, and a Finding on (release R′, F) in a
release **of the same project** holds a judged Position (D4), Governance raises a system proposal
on the target with the precedent's stance, proposer `system:roll-forward`, id
`rollforward:<target>:<source>` (deterministic, so a re-run raises nothing new), and a rationale
naming the source release, the Position version, who decided it, the level (D3) and the original
rationale verbatim. The Position is not copied, the stance is not applied, and no event claims a
decision was taken.

Why same project: a project is the line of releases that succeed one another (Registry's
Product → Project → Release), which is the only sense in which "the previous release" is defined.
A decision on a sibling product's release is a different enterprise question and stays precedent
for the AI road only (EDR-INTELLIGENCE-01 C6), where a person reads it as a suggestion.

### D2 — The proposal rests on Inferred evidence, so no policy can ever accept it

A decision carried from another release is a hypothesis about this one. The proposal is stamped
`TrustInferred`, and the constitutional check (EDR-TRUST-01 T6) runs before any policy, so the
shipped `not_affected`-on-Observed rule and any future rule are structurally unable to accept it.
A roll-forward proposal is decided by a person or not at all.

### D3 — Granularity: artifact and component level may propose; vulnerability level may not

Themis has one Position per Finding and no per-component Position. The three VAMS levels are
expressed as a rule over the two Findings' **active carrier components** (retired matches and
scope-class components take no part — a decision is about what carries the flaw, and unknown
acts as carrier as everywhere):

| level | rule | proposed? |
| --- | --- | --- |
| artifact | the same purls, version for version | yes, named `artifact level` |
| component | the same packages (purl without version or qualifiers), any versions | yes, named `component level` |
| vulnerability | only the CVE is shared; the components differ, or the target has no carrier | **no** |

Vulnerability-level reuse is not proposed because a decision taken about one component says
nothing about a different one, and because the fixture demands it: a scope-only target has no
subject to take a stance about (EDR-ATTRIBUTION-01 D12, `no_subject`), whatever was decided
elsewhere. Both proposed levels name themselves in the rationale, so the person deciding sees
whether the version moved.

### D4 — Only a judgement is carried: a rule's verdict re-derives on its own

A Position a policy established, or one that accepted a **system**-raised proposal (the
version-range verdict, a vendor statement) — whoever clicked accept — is arithmetic about that
release's own facts, and the same rules re-run on the new release when its facts hold. Carrying it
would propose the conclusion without the premise. The precedent must be a human decision on a
human or AI proposal (`Finding.JudgedPosition`), the same line AI-RF-4/4b drew for the precedent
index. Among several judged siblings, the most recently established wins.

### D5 — It runs where Registry may fail without stopping the pipeline

The release → project hop is a Registry read, and a handler error on the bus reader's inbox
transaction halts the Knowledge stream after five attempts (EDR-EVENTBUS-01 D8). So roll-forward
does not run when a Finding opens. It runs on the **release-evaluation worker** (EDR-DELIVERY-01
N-M2b), after a release's correlation completes and its project is resolved, **before**
publish-and-mark: a Registry failure defers the row and the pass is retried; the pair id makes the
retry idempotent. The project hop for a sibling runs last, only for a sibling that qualified on
every other count, so an estate with no judged siblings costs no Registry calls.

For the Findings an estate already holds, the one-time re-judge pass
(`THEMIS_GOVERNANCE_REJUDGE_RANGES=1`, KN-GO-2) also sweeps roll-forward when a Registry seam is
configured, and logs `rollforward_raised`.

### D6 — The AI road is unchanged and remains the semantic complement

`recommend_position` and the Δ4b sweep still ground on same-CVE precedent first (AI-RF-1) and on
semantic neighbours after, across products, with a model in the path and a person deciding. The
deterministic proposal is the rule-first core; the AI remains the optional enhancement on it, and a
Finding may carry both — a roll-forward proposal and an AI proposal — which is exactly the
situation a human should see.

## Not decided here

- **Review-by has no timer** (audit B3): a suppressed Finding whose review date passes is only
  re-surfaced on an enrichment. A small Governance sweep; tracked separately.
- **Raising at Finding creation** (VEX-RAISE-2) would also let roll-forward run at open time; it
  needs the Registry hop off the inbox transaction first, which is the N-M2b split again.
- A roll-forward proposal from a **different product's** release is not raised. If an estate
  shows a real case, it is a new decision, not a relaxation of D1.

## Traceability

Implementation: `internal/governance/domain/rollforward.go` (D3, D4),
`internal/governance/app/rollforward.go` (D1, D2, D5), `worker_release_evaluation.go` and
`rejudge.go` hooks (D5), `store.UndecidedFindingsByRelease`. Fixture:
`TestRollForward_DoesNotProposeAcrossProjectsRulesOrPackages` (scope-only target, CVE-2026-33006).
OpenSpec: `openspec/changes/phase3-rollforward`.
