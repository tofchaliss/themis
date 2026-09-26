# EDR-HARNESS-01 — The AI Runtime integration: commissions, execution evidence, the decision door

Status: **Accepted 2026-09-26** — the decisions were grilled and locked with the user in the
`themis-ai-runtime` repository (`openspec/changes/themis-integration/design.md` D-I-1..9,
`themis-commissioning/design.md` D-C-1..6, `l8-themis-surface/design.md` D-L-1..3,
`l11-governance-promotion/design.md` D-R-1..4, and the runtime-side `l5-witness-events/design.md`
D-W-1..6). This EDR records what those decisions require of THEMIS, so the Themis-side
implementation has a reason of record in this repository. Where they disagree, the runtime-side
design records win for runtime facts and this EDR wins for Themis domain facts.

Closes the deferred question in **EDR-TRUST-01** ("the Decision Proposal payload cannot be designed
before a second Decision capability exists to shape it"): the AI runtime is that capability.

## Purpose

The AI runtime (`github.com/tofchaliss/themis-ai-runtime/src/harness`) executes governed,
bounded, reconstructable work. Themis is the system of record for security truth. The integration
must let Themis use an execution as evidence for a Governance decision without the runtime ever
becoming a Governance actor, and without Themis ever depending on the runtime's orchestration or
interpreting its internals.

## Decisions (Themis side)

### D1 — Commissioning is a pre-execution Governance act (D-C-1, D-C-2)
A **Commission** is an immutable, append-only authority record on a Finding: Themis-minted id,
the commissioned method (`skill name@version` + composition hash) and deployment (anchor
`name@version` + artifact hash) as OPAQUE strings, the commissioning human (`key:<KeyID>`,
server-derived), a descriptive premise (stage + Position version observed), a rationale, and
raised-at. It contains no task id, no runtime inputs, no outcome. Themis validates none of the
runtime's registries at commission time (they are the runtime's; Themis equality-checks later).

### D2 — Lifecycle: reusable authority, forward-only withdrawal (D-C-3)
`open → withdrawn` by any authenticated human, with its own witness and rationale. Many
executions may cite one commission. Withdrawal is evaluated at PROPOSAL time on Themis's own
sequence; it never invalidates recorded executions and never rewrites history. No expiry.

### D3 — No Finding-stage effect (D-C-4)
Commissioning is allowed at every non-terminal stage (Archived refuses) and moves no stage. The
premise is observational. `FindingCommissioned` / `CommissionWithdrawn` are thin, Governance-
internal events; Communication does not consume them.

### D4 — Who may commission (D-C-6)
Authenticated write-capable humans only (never AI/policy/system). The runtime cannot commission
(its credential is read-scoped). Commissioner may equal proposer; decider must differ —
operationally, not as a Governance invariant. Known gap carried: `AuthorizeWrite` does not confine
`product:<id>` to that product's Findings (row 14 of the integration matrix).

### D5 — The proposal's evidence is first-class and its trust is DERIVED (D-I-5)
A proposal whose basis is a runtime execution is raised by a HUMAN with an immutable
`harness-execution/v1` evidence object (commission id; anchor hash/name@version/state at intake;
task id; artifact-bound seq; artifact object id; verified member path+hash; skill+composition;
contract name@version/hash/state; reconstruction verdict; production witness; constitution hash;
harness module; delegation count+seqs; business refs). Governance validates the SHAPE and never
re-resolves the runtime record. The trust class is `inferred` by derivation (a model-authored
artifact; an L10 PASS is admissibility, not authorship); a submitted class other than the derived
one is refused. Business Verification (EDR-TRUST-01 T8) runs on refs taken from the RECORDED
Finding bytes the execution read.

### D6 — Correspondence at proposal time (D-C-5)
In causal order, first failure named: commission exists on THIS Finding → open → method equals
the recorded skill+composition → deployment equals the recorded anchor name@version+hash. Equality
only; no interpretation. Only an L5-witnessed, consistent-PASS execution is proposal-eligible
(D-W-5, D-L-2); an `l6-record-only` execution is inspectable history.

### D7 — The decision door is unchanged (D-I-6)
`acceptProposal` by an authenticated principal (`key:<KeyID>`, EDR-SECURITY-01 D10) establishes
the Position; the Position cites the accepted proposal, which carries the evidence by value and
the runtime record by reference. No second Position mechanism.

### D8 — Placement and walls (D-I-1, D-I-7, D-R-4)
`internal/governance/adapters/harness` is the ONLY Themis package that imports the runtime, and
only its read-only record contracts (`state`, `deployment`, `verification`, `verification/seam`);
depguard and `tests/architecture` enforce it. `cmd/themis-intake` (human-operated, same host as
the runtime record plane) consumes the adapter and raises the proposal over the authenticated
API; the Governance service never links the adapter and never reads the record plane. The intake
DERIVES the commission id from the runtime's CREATED event and accepts no override.

### D9 — Delegations are rendered, never adjudicated (D-L-1, D-L-2, D-L-3)
`l8-delegation` witnesses appear in the evidence view within the model-reasoning fact and in the
evidence by seq; no delegation-specific admissibility rule exists while runtime delegates stay
tool-less — a premise (`l8-delegates-tool-less`) every witnessing constitution in the adapter's
table re-affirms.

## Honest limits

- The `harness-execution/v1` evidence is as true as `themis-intake`'s reconstruction; Governance
  does not re-run it. The runtime record remains the evidence; the proposal is the reference.
- Product-scope write confinement (D4) is a pre-existing authorization gap, not created here.
- The runtime dependency pin (`go.mod`) is added when the runtime commit is published; until
  then the repository builds only inside a `go.work` that includes the runtime checkout.

## Realizes

CON-0002 (proposal before truth), CON-0003 (explainable history), DOM-0024 (AI proposes, never
decides), EDR-TRUST-01 T2/T3/T4/T8, EDR-SECURITY-01 D10, EDR-GOVERNANCE-01 D3/D4/D7/D8.
