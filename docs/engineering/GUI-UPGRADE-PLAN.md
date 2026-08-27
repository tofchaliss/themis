# GUI upgrade — plan, AI use cases, and discussion minutes

**Status: DISCUSSION DOCUMENT — 2026-08-12.** Nothing in here is committed-to until discussed;
the Minutes section at the end records what each session actually decided. When the GUI is
productized (GUI-6) this document feeds the EDR; until then it is the thinking companion to
[`DASHBOARD-SPIKE.md`](DASHBOARD-SPIKE.md) (which describes what *exists*) and
[`../BACKLOG.md`](../BACKLOG.md) §C (which tracks what is *open*).

---

## 1. The one-paragraph picture (plain English)

We put a GUI in front of Themis for the first time, and it worked: a security engineer can walk
the estate, open a release's posture, open one vulnerability, see what it is, see how similar
cases were decided before, ask the AI for advice, decide, and publish — all against the live
APIs, storing nothing of its own. The live days surfaced eleven open items in two families:
**GUI-1…6** (what the human in front of the screen still lacks — mostly *data* gaps the GUI
exposed, plus productization) and **G-AI-1…5** (what the AI harness still lacks — escalation,
budgets, gathering, all backend). This document plans both families, maps every dependency
between them — including the places where we looked and found none — and opens the discussion
the user asked for: **how the AI should show up in the GUI**, starting from a concrete defect
(you ask the AI for a recommendation, it answers, and the screen tells you to go reopen the
drawer to read it).

---

## 2. Item-by-item plan

Effort scale: **S** = a focused session · **M** = a few sessions, one EDR delta ·
**L** = its own change with an EDR + OpenSpec tasks.

### GUI-1 — AI "explain this vulnerability in our context" (Information capability)

- **What it is (example first):** the drawer today shows the stored feed summary — *"Log4j JNDI
  features do not protect against attacker-controlled endpoints"*. What no feed can say is:
  *"…and your `python3-libs` sits in billing-api's request path, reachable by 12 customers, and
  your version is two releases behind the fix."* That sentence needs enterprise context — the
  assessment projection, the blast radius, the fix attribution — which is exactly what an
  Information-class capability (T7) is for.
- **Plan:** new capability `explain_vulnerability@v1` in Intelligence, same class and path as
  `plan_remediation` (Information → ephemeral, nothing enters Governance, worst outcome is a
  human disagreeing). Grounded ON the stored summary + the T10 assessment projection — never a
  substitute for the stored summary (that layering was decided 2026-08-11 when the summary was
  made evidence; see the `VulnFacts.Summary` doc comment). GUI: an "Explain in our context"
  button in the drawer, output clearly AI-labeled, never persisted.
- **Effort:** M (capability + prompt + grounding gate + one GUI section).
- **Dependencies:** stored CVE summary (**done**, `feat/knowledge-cve-summary`) · assessment
  projection (**done**, T10) · the Information-capability pattern (**done**, `plan_remediation`).
  Soft: G-AI-4 budget (already metered per capability — config exists, nothing new needed).
  **No dependency on GUI-2…5.** Cluster **R1**.

### GUI-2 — Alpine secdb enrichment feed

> **Status: bounds half ✅ SHIPPED 2026-08-13** (EDR-VEX-01 D7, PR #95; live-verified — 78 bounds
> folded). The apk fixed-VERDICT continues as **GUI-2b** — tracked in `docs/BACKLOG.md`, the one
> tracking document.

- **What it is:** the one genuine distro *data* gap the live days found. RHEL/Rocky/Alma get
  vendor severity + `not_affected` + fixed NEVRAs from the Red Hat feed; Ubuntu/Debian ride
  OSV; **Alpine has correlation only** — no vendor fixed-version bounds, no apk fixed-verdict.
- **Plan:** write the **D5 reading first** as an EDR-VEX-01 delta — the secdb is not per-CVE
  addressable, so the shape is: fetch the small per-branch DB, fold ONLY records matching
  carded CVEs, discard the rest (enrichment, never mirroring). Then a feed ACL mirroring B3's
  shape, opt-in (`THEMIS_ALPINE_ENABLED=1`), producing source Proposals like every other feed.
- **Effort:** M. **Priority: MED-HIGH for estates shipping Alpine** — highest-graded item in
  either family.
- **Dependencies:** none hard. Soft synergy with GUI-4 (a new `alpine` feed-health row falls out
  of the existing machinery) and GUI-5 (whichever of GUI-2/GUI-5 goes first establishes the
  "fold a non-per-CVE vendor DB" pattern the other reuses).

### GUI-3 — Red Hat `changes.csv` modified-since sweep

- **What it is:** efficiency, not correctness. The Red Hat feed re-asks Hydra per carded CVE per
  interval; `…/csaf/v2/advisories/changes.csv` is a change signal — intersect with carded CVEs,
  fetch only what moved.
- **Plan:** **step zero is a verification, not code** — check whether `THEMIS_VEXFEED_URLS`
  pointed at Red Hat's per-CVE VEX directory already covers the need with zero new code. Only if
  not: add the changes.csv sweep under the same D5 bound.
- **Effort:** S (possibly zero). **Dependencies: none identified** — independent of every other
  item in both families.

### GUI-4 — per-distro feed-health rows

> **Status: ✅ SHIPPED 2026-08-13** (PR #95, `adapters/feed/health_source.go`; live-verified —
> `osv/rocky` row).

- **What it is:** visibility. `GET /feeds` shows one `osv` row, so "Alpine data flowing" and
  "Alpine data quietly absent" look identical on the dashboard's feed-health view; RHEL + Rocky
  + Alma hide behind one `redhat` row.
- **Plan:** record OSV distro queries per ecosystem (`osv/alpine`, `osv/rocky`, …) in the
  feed-health store; the dashboard's existing feed view renders whatever rows arrive, so the
  GUI cost is near zero.
- **Effort:** S. **Dependencies:** none hard. Note it is the *visibility half* of what was
  reported as "add feeds for rhel/rocky/alpine" — the rhel/rocky DATA already flows; only
  Alpine (GUI-2) is a real gap. Doing GUI-4 **before** GUI-2 makes the Alpine gap visible on
  screen, which is a nice order but not a dependency.

### GUI-5 — Rocky errata feed for RXSA-only advisories

- **What it is:** the Red Hat feed covers Rocky by clone (correct for rebuilds — EDR-VEX-01
  decision), but **RXSA** advisories (Rocky-exclusive/SIG packages) exist in no Red Hat data.
- **Plan:** a Rocky errata (Apollo) feed scoped strictly to the RXSA gap; do not duplicate the
  clone coverage. Same D5 EDR-delta-first discipline as GUI-2.
- **Effort:** M. **Dependencies:** soft — reuses the GUI-2 pattern if GUI-2 goes first;
  otherwise independent.

### GUI-6 — productize the dashboard

- **What it is:** the spike branch never merges. When the VM evaluation settles style and
  feature set, the keeper is rebuilt properly: **EDR + OpenSpec change**, auth on its own
  inbound edge (`internal/platform/auth`, like every other node), the authority-line buttons
  *designed* rather than spiked, handler/proxy tests, coverage registration.
- **Plan:** (1) finish the VM evaluation rounds (this document's discussion feeds them);
  (2) write `EDR-GUI-01` — the spike doc + this doc are the requirements capture; (3) OpenSpec
  change; (4) rebuild on a fresh branch; (5) delete the spike branch.
- **Effort:** L. **Dependencies:** the VM evaluation *settling* (a decision, not code) · real
  authentication answering `/whoami` — the recorded proposer/actor on every decision is whatever
  `/whoami` returns, so **GUI-6 must precede any deployment where "who decided" matters**. F1
  auth exists and is the seam; what is missing is the dashboard wiring + a real identity story.
  GUI-7/8/9 (filed today, §6) fold into either spike iteration or GUI-6's design.
- **Identity decided 2026-08-12 (D5):** v1 = a **small set of named, API-key-backed operators**
  via `internal/platform/auth` scopes — each operator gets a named key (`authadmin create-key
  --name alice`), the dashboard resolves `/whoami` from the presented key, and the recorded
  proposer/actor becomes that name. No full user management in v1.

### G-AI-1 — on-demand "fresh-CVE" gathering: the AI asks, the feeds gather

- **What it is:** `recommend_position` against a CVE our feeds have not ingested returns an
  honest `insufficient` — correct, but a dead end. The go-forward design: the AI emits a
  structured **"need more data on CVE-X"** flag — itself Information, never a write — and the
  Knowledge/feeds side consumes it to gather (an on-demand/crawler feed source producing source
  Proposals like any other feed). "Gathering Is Not Knowing" stays intact: the AI only asks.
- **Effort:** L. **Dependencies:** (a) an on-demand feed source on the Knowledge side (feed ACL
  machinery **exists**; the on-demand trigger does not) · (b) the Intelligence "need-more-data"
  output + its **push seam — Δ4-class**, the same seam Δ4 autonomy needs. **GUI tie-in:** the
  drawer's 204 toast could one day say "gathering — ask again in a minute" instead of a bare
  `insufficient`; that surface lands with GUI-9 (§6).

### G-AI-2 — "can't determine" as a first-class improvement signal

- **Status:** (a) the **rate is observable — LANDED 2026-08-07**
  (`themis_ai_invocations_total{capability,reason,produced}`). Open: (b) **escalation** — retry
  with a larger/different model, the upgrade counterpart of degrade-not-fail; (c) **the eval
  loop** — a capability that says "can't tell" too often gets its prompt/model version tuned.
- **Effort:** (b) M once the router exists · (c) L (Δ4 LLMOps plane).
- **Dependencies:** (b) needs the **model router** (D6/INT-0062) and a **second chat model on
  the box — today there is exactly one; clearing that is one `ollama pull`**. (c) needs Δ4.
  The router is shared with G-AI-4's degrade-not-fail and G-AI-5's clearance routing — **build
  it once, three items advance.**

### G-AI-3 — rank precedent decisions by release-to-release delta

- **Status:** the semantic half **landed with Δ3a** — `recommend_position` retrieves
  cosine-similar past Positions. Open remainder: **weight that precedent by how close each past
  release is to the one under judgment** — a decision on a near-identical release should carry
  weight; one on a very different release should be down-weighted, not blindly trusted.
- **Effort:** L. **Dependencies:** a **Registry/Evidence release-comparison read API that does
  not exist** (component/usage deltas across Releases — a "Must ask" new API surface). Overlaps
  the R5-deferred Δ3a component-embedding design item. **No GUI dependency identified**, though
  the same delta signal would improve the drawer's "Similar past decisions" ordering for free.

### G-AI-4 — budget enforcement (remainder)

- **Status:** **partially closed 2026-08-09** — the per-capability window ceiling is enforced
  (`THEMIS_INTELLIGENCE_BUDGET_TOKENS`/`_WINDOW`; every attempt debits; exhaustion is its own
  reason `budget_exhausted`). Open: the other three scopes (per-run cost ceiling, autonomous
  pool, global enterprise ceiling) and **degrade-not-fail model downgrade**.
- **Effort:** M–L. **Dependencies:** degrade-not-fail needs the **model router + second model**
  (shared blocker with G-AI-2b) · the autonomous-pool scope only means anything once Δ4
  autonomy exists · the global scope wants the operational store + Governance-owned budget
  policy config. Enforcement bites for real only when paid/cloud providers arrive.

### G-AI-5 — data-classification / provider-clearance admission

- **Status:** deliberately minimal while **local-only** — nothing leaves the building, so
  INT-0069's strongest rule is satisfied by default; the path is hard-marked local-only.
- **Plan:** full classification → clearance routing (classify each assembled context, route
  each class only to cleared providers, residency limits, output-filter responses) **when a
  cloud/paid provider exists** — classification only changes routing once there is a non-local
  destination.
- **Effort:** L, deferred by design. **Dependencies:** multiple providers + the model router +
  Governance-owned clearance policy config. **GUI tie-in (small, cheap, honest):** surface the
  "local-only" badge in the GUI's AI sections — users deciding whether to paste context into an
  AI box deserve to see where it goes. Lands with GUI-9.

---

## 3. Dependency map

```text
                 ┌────────────────────────────────────────────────────┐
                 │ SHARED BLOCKERS (build once, several items advance)│
                 └────────────────────────────────────────────────────┘
  Model router (D6) + 2nd chat model ──► G-AI-2b escalation
       (one `ollama pull` clears the  ──► G-AI-4 degrade-not-fail
        second-model half)            ──► G-AI-5 clearance routing
  Δ4 plane (op-store · push seam ·    ──► G-AI-1 (push seam)
        eval loop / LLMOps)           ──► G-AI-2c (eval loop)
                                      ──► G-AI-4 autonomous-pool scope
  D5 "EDR-delta first" feed discipline──► GUI-2 · GUI-3 · GUI-5
  Release-comparison read API (new)   ──► G-AI-3 (sole consumer so far)
  Real authentication (identity)      ──► GUI-6 (recorded proposer/actor)

  Soft orderings (nice, not required):
    GUI-4 before GUI-2   — makes the Alpine gap visible before filling it
    GUI-2 before GUI-5   — establishes the fold-a-vendor-DB pattern
    GUI-1 before GUI-6   — spike the capability, productize its surface

  Explicitly checked, NO dependency found:
    GUI-3 ↔ everything          (pure feed efficiency; step zero may be config-only)
    GUI-1 ↔ GUI-2/3/4/5         (the explain capability grounds on data already stored)
    GUI-2/3/4/5 ↔ any G-AI item (feed work and harness work do not touch)
    G-AI-3 ↔ any GUI item       (its blocker is a backend read API)
```

The load-bearing observation: **the eleven items reduce to five blockers**, and two of those
(model router, D5 delta) are small. Only the Δ4 plane and the release-comparison API are
genuinely large. Nothing in the GUI family blocks anything in the G-AI family or vice versa —
the two tracks can proceed in parallel by different hands.

---

## 4. AI × GUI — the discussion the user asked for

### 4.1 The two-click problem (defect, confirmed in code — GUI-7) — ✅ FIXED 2026-08-12

**Implemented on the spike per D3** (reload + one-shot highlight into "Proposals on record" +
an honest "may take a minute" progress label). The description below is kept as the record of
what was wrong and why the fix took this shape.

**What happens today:** in the drawer you press "Recommend a position". The backend does the
whole job in one round trip — invokes the Gateway, records the advisory proposal, returns
**201 with the proposal id**. The dashboard then shows a toast: *"Advisory proposal recorded —
reopen the drawer to see it."* (`cmd/dashboard/static/app.js:847`). You asked a question,
the answer arrived, and the screen tells you to go look for it.

**Why it is trivial to fix:** four lines above sits `reload()` — the exact helper the human
decision buttons already call after accept/reject. On 201, call it. The refreshed drawer shows
the new proposal in "Proposals on record" with its stance, rationale, trust chip, and
accept/reject buttons — no new endpoint, no new state.

**The better version worth discussing:** don't just reload — *highlight* the arrived proposal
(scroll to it, one-shot emphasis) so the eye lands on the answer to the question just asked.
And while it runs, the button should show progress honestly: a recommendation takes seconds to
minutes (local model, 300s timeouts on the VM) — a dead button for 45 seconds reads as broken.

### 4.2 AI enrichment — "explain this vulnerability in our context" (GUI-1)

The layering decided 2026-08-11 holds and is worth restating because it is the design rule for
*every* AI text in the GUI:

| Layer | What | Trust | Persisted? |
| --- | --- | --- | --- |
| Stored summary | what the feeds say the CVE **is** | evidence (Asserted) | yes — on the card |
| AI explanation | what it means **for us** | Inferred, AI-labeled | no — ephemeral |

The stored summary is evidence and renders first; the AI explanation is an optional overlay a
user *requests*, clearly labeled, never cached into anything. This is T7 applied to prose: an
Information capability's worst outcome is a human disagreeing with a paragraph.

**DECIDED 2026-08-12 (D1): the explanation AUTO-RUNS when the drawer opens.** The user chose
immediacy over consent friction; the spend-per-open trade is accepted and handled in design
instead:

1. **Session cache** — the browser caches the explanation per finding for the session
   (in-memory only, never persisted), so re-opening the same drawer costs nothing. The budget
   meter (G-AI-4) remains the backstop against runaway spend.
2. **Non-blocking load** — the drawer renders its evidence (summary, proposals, precedents)
   immediately; the AI section fills in when the capability returns and states plainly while it
   runs ("explaining — local model, may take a minute"). The drawer must never wait on the AI.
3. **Enabled-only** — the section renders only when the Intelligence node is reachable and the
   capability enabled; a disabled AI plane leaves no dead placeholder.

### 4.3 The AI capability the GUI doesn't show at all: `plan_remediation`

Checked today: **no code in `app.js` calls it.** The capability ships, the Intelligence node
serves `POST /capabilities/plan_remediation@v1/invoke`, the dashboard proxy already routes
`/api/intelligence/*` — and the release posture view, which shows the 231 findings the plan
would group into ~12 package upgrades, offers no way to ask. This is the single cheapest
AI-value-add available: one button on the posture view, zero backend work. Filed as GUI-8.

**OPEN (D2, 2026-08-12): rendering shape needs more discussion.** The three candidates, with
their trades, as input for that discussion:

| Shape | For | Against |
| --- | --- | --- |
| **Modal** | zero layout change; obviously ephemeral | a ~12-step plan in a modal scrolls badly; can't sit beside the findings table it groups |
| **Posture-view section** | the plan lands next to the 231 findings it explains; comparable side-by-side | takes permanent page real estate for an on-demand artifact |
| **Borrowed artifact layout** (Publication-like page, not a Publication) | print/share-friendly; room for the full grouping + fix versions | a second page that *looks* stored — must be loudly labeled ephemeral to avoid implying persistence |

**RESOLVED 2026-08-12 (D2 superseded by D6):** the user directed "finish all the GUI changes"
for a VM test round, which settles D2 pragmatically — the **posture-view card** (collapsed
until asked) shipped, per the leaning above: the plan's whole value is its relationship to the
findings list it condenses. The VM round judges the shape; a modal or artifact layout remains a
cheap swap if it reads wrong.

### 4.4 AI transparency — the GUI should show what the harness already knows (GUI-9)

The backend states facts about every AI interaction that the GUI currently drops or hides in a
transient toast:

- **The 204 reason taxonomy** (`X-Themis-AI-Reason`: `disabled` · `unreachable` ·
  `insufficient` · `provider_error` · `budget_exhausted` · `business_invalid`) — today a toast
  that vanishes. `insufficient` is the seam *working*; `unreachable` is an ops problem. The UI
  should render them differently.
- **`precedents_used`** — surfaced on the API precisely because it is "the only externally
  visible evidence that the retrieval plane contributed at all" — the GUI doesn't show it.
- **`decided_by`** (`rule:<stance>` vs `llm:<stance>`) — whether a deterministic rule or the
  model decided is exactly what a skeptical engineer wants to know, and it changes how much
  scrutiny the proposal deserves.
- **Local-only badge** (G-AI-5) — where the prompt goes. One static chip today; becomes real
  routing info when cloud providers arrive.
- **Budget state** (G-AI-4) — `budget_exhausted` should be legible as "spend ceiling, resets at
  HH:MM", not a mystery no-answer.

The principle: **the harness was built honest — the GUI should not launder that honesty into a
generic spinner-and-toast.** Every reason, provenance stamp, and grounding count that exists on
the wire should be visible where the human decides.

### 4.5 What the GUI will deliberately never do (standing guardrails, restated)

- No AI output is ever rendered as if it were a stored fact — AI text is labeled, every time.
- The GUI never auto-accepts anything; "Raise & accept" stays two recorded audit steps.
- An `inferred` proposal keeps its "policy cannot auto-accept this; you can" label — the
  buttons ARE the human decision T4 reserves.
- No API key in the browser; the proxy injects it (already true, stays true through GUI-6).

---

## 5. Suggested sequencing (recommendation, not decision)

| Order | What | Why first |
| --- | --- | --- |
| 1 | GUI-7 (two-click fix) + GUI-9 (transparency) on the spike | S-sized, pure `app.js`, sharpens the very evaluation the spike exists for |
| 2 | GUI-8 (`plan_remediation` button) | cheapest new AI value; zero backend |
| 3 | GUI-4 then GUI-2 (per-distro rows, then Alpine) | make the gap visible, then fill the MED-HIGH data gap |
| 4 | GUI-1 (explain capability) | first *new* capability; pattern exists |
| 5 | Model router (+ 2nd model) → G-AI-2b + G-AI-4 degrade | one build unblocks three items |
| 6 | GUI-6 (productize, EDR first) | after the evaluation settles — informed by 1–4 |
| later | GUI-3 (verify-first) · GUI-5 · G-AI-3 · G-AI-1 · G-AI-2c · G-AI-5 | independent / Δ4-gated |

**DECIDED 2026-08-12 (D4): the GUI track goes first.** The backlog's standing advice — that R7
(GOV-15) and R6 (F5, rotation) outrank feature work as measured correctness/operability
defects — is consciously overridden by the user for this period; rows 1–4 proceed now. R7/R6
remain the highest-priority *non-GUI* work and should be picked up the moment the GUI track
pauses.

---

## 6. Issues filed today (2026-08-12) — GUI batch 2

Filed in `docs/BACKLOG.md` §C per the standing filing rule (cluster + measured/read-from-code):

- **GUI-7 — the AI recommendation demands a second click to be seen.** User observation on the
  VM + confirmed in code (`app.js:847`). Fix: `reload()` on 201 + highlight + honest progress
  state. Cluster: spike iteration → GUI-6.
- **GUI-8 — `plan_remediation` has no GUI surface.** Read from code (no caller in `app.js`;
  endpoint + proxy route exist). One button on the posture view. Cluster: spike → GUI-6.
- **GUI-9 — AI transparency panel.** Read from code: reason taxonomy, `precedents_used`,
  `decided_by`, local-only badge, budget state all exist on the wire and are dropped or
  toast-transient in the view. Cluster: spike → GUI-6 (and the natural home for G-AI-1's
  "gathering" state and G-AI-4's budget display when those land).

---

## 7. Minutes

### Session 2026-08-12 — planning + AI×GUI discussion (user + Claude)

**Asked for:** a complete plan for GUI-1…6 and G-AI-1…5 with dependencies (or an explicit
"none identified"); an engineering document for the coming GUI upgrade; a deliberate slow-down
into discussion, specifically on AI use cases in the GUI.

**Established (fact-finding):**

1. The two-click recommendation flow is real and located: on 201 the dashboard toasts "reopen
   the drawer" instead of calling its own existing `reload()` (`app.js:847`).
2. `plan_remediation` is not reachable from the GUI despite the endpoint and proxy route
   existing.
3. The eleven planned items reduce to five shared blockers (model router · Δ4 plane · D5 feed
   discipline · release-comparison API · real auth); the GUI family and the G-AI family have
   **no hard dependencies on each other**.

**Decided this session:**

1. This document exists and is the discussion record; DASHBOARD-SPIKE.md stays the description
   of what is running.
2. GUI-7/8/9 filed as backlog items (batch 2), per the standing filing rule.
3. Nothing coded yet — the two-click fix is deliberately held for the discussion the user
   requested, despite being small.

**Open questions raised (answered same day — see below):** Q1 explain trigger · Q2 plan
rendering · Q3 recommendation display · Q4 track priority · Q5 GUI-6 identity.

### Session 2026-08-12 (later) — decisions on Q1–Q5 (user)

- **D1 (Q1): GUI-1 explain AUTO-RUNS when the drawer opens.** User decision, overriding the
  behind-a-click recommendation; the trade (spend per drawer-open) is accepted and mitigated in
  design, not by consent friction — see §4.2 for the three mitigations (session cache ·
  non-blocking load · enabled-only).
- **D2 (Q2): remediation-plan rendering stays OPEN — discuss more.** §4.3 now carries the
  three candidate shapes with trade-offs, as input for that discussion. GUI-8 implementation is
  held until this is decided.
- **D3 (Q3): one place.** The recommendation flow reloads the drawer and highlights the arrived
  proposal inside "Proposals on record" — no second rendering path. This settles GUI-7's design.
- **D4 (Q4): the GUI track goes first.** §5 rows 1–4 proceed ahead of R7/R6; the backlog's
  standing advice is consciously overridden by the user for this period.
- **D5 (Q5): GUI-6 v1 identity = a small set of named, API-key-backed operators** via
  `internal/platform/auth` scopes — no full user management in v1.

**Acted on immediately after D3/D4:** GUI-7 implemented on the spike branch (reload +
highlight + honest in-progress state; see §4.1). GUI-8 held on D2; GUI-1 auto-run is its own
capability-building session (backend first).

### Session 2026-08-12 (later still) — "finish all the GUI changes, then we test" (user)

- **D6:** finish the remaining pure-GUI items now; the user runs the VM test round on the
  result. This supersedes D2's "discuss more" — GUI-8 shipped in the posture-card shape (§4.3).
- **Shipped on the spike, all verified (`node --check` + `go build`):**
  - **GUI-8** — the "Draft a remediation plan" card on the release posture view: invokes
    `plan_remediation@v1` against `{subject:{type:release}}`, renders the ephemeral
    `InformationResponse` with `decided_by` + `precedents_used` chips, marks `[UNVERIFIED
    MENTIONS …]` caveats with a wavy warn underline (readable in both themes — amber *text* on
    the light card fails contrast), and explains every 204 via the shared reason panel.
  - **GUI-9** — the transparency layer: the six-reason `X-Themis-AI-Reason` taxonomy rendered
    as a persistent labeled panel in the drawer (replacing the vanishing toast), `local-only`
    chips on both AI surfaces, provenance chips wherever the wire carries them.
- **Scope line drawn:** "all the GUI changes" = the pure-GUI spike items (GUI-7/8/9 — now all
  closed). GUI-1 (new backend capability), GUI-2/3/4/5 (feed work), and GUI-6 (productization)
  are backend/design work and were not silently pulled into this session.
- **Known bound, recorded:** the drawer's *recorded* proposals still show AI provenance only as
  rationale prose — structured per-proposal fields are R2's item, not a GUI patch.
- **Next:** the user's VM test round → findings filed under `GUI-` in the backlog → then the
  track continues per §5 (GUI-4 → GUI-2 → GUI-1 backend-first).

### Session 2026-08-12 (evening) — the VM test round: FULL PASS (user testing, Claude triaging)

Every step of the five-step script passed, and the round paid for itself several times over:

- **Passed:** GUI-7 (recommendation lands in the drawer, highlighted) · GUI-9 honest-decline,
  unreachable, and budget-exhausted panels (three distinct reasons, correctly styled) · GUI-8
  on both a carrier-rich release (15-step plan, `llm:information`) and the scope-only perl
  release (CVE-2026-42496 contributed NO step — carriers-only held on both AI paths) · both
  themes · the full decision flow raise → accept → publish → **read the document**.
- **Found + fixed same-day (no backlog entries, per the round's convention):** the capability
  route id is the bare name, not the `@v1` ref (404 on first plan attempt — the compiler-less
  URL seam); **publications listed but not openable** — rows now open a document overlay with
  pretty-print + download off `GET /publications/{id}`.
- **Found + filed:** **AI-204-2** (an honest decline should state its deterministic sub-cause —
  the zero-carrier diagnosis took a three-service API walk a one-word detail would have saved);
  three measured grouping observations on **PLAN-5** (name-case split, module-stream fan-out
  step, CPython-flaw-attributed-to-ply/PyYAML — the third seen on two releases); a measured
  live confirmation on the **Δ3a conflation** item; and a live **T8** catch (a real release
  UUID in a produced rationale).
- **Deliberately not built:** a preview for the publishable QUEUE (`POST /previews` exists;
  it is a new flow → GUI-6).
- **Standing verdict for GUI-6:** the spike's core bet (posture-first navigation, the drawer
  as the decision surface, the proxy pattern) survived a full working day of live use by its
  intended user with zero navigation complaints — the productization can inherit the layout.

### Session 2026-08-12 (night) — "let us start GUI-4, 2, 1, 6" (user directive; Claude building)

The track's next four items, in the decided order. Branch discipline: mergeable backend work on
feature branches off `main` (the spike never merges), merged INTO the spike for VM testing.

- **GUI-4 — DONE** (`feat/knowledge-distro-feeds`): per-distro OSV health rows (`osv/alpine`,
  `osv/rocky`, …) at Tier-3, so a quiet distro reads as an old timestamp and never as a degraded
  feed; the aggregate `osv` row keeps the tier-2 verdict. `make check-ci` green.
- **GUI-2 — bounds-first half DONE** (same branch): **EDR-VEX-01 D7** written first (the D5
  reading — fetch the branch DB whole, fold only carded CVEs, discard the rest in memory), then
  the `alpine` feed (ACL + client + sweep, trust=Observed, tier=2, opt-in
  `THEMIS_ALPINE_ENABLED`/`_BRANCHES`). The **apk fixed-verdict** split out as **GUI-2b**,
  exactly as Red Hat split PR2/PR3. `make check-ci` green — and `vet-tags` earned its keep again
  (the tagged pipeline-test `Wire` caller).
- **GUI-1 — DONE** (`feat/intelligence-explain`, **stacked on `feat/knowledge-cve-summary`**):
  `explain_vulnerability@v1`, the third capability — Information (T7), one Finding, grounded on
  the stored summary + assessment projection, no precedent step, Grounding Verification the only
  gate, a third real-model case in `make e2e-llm`. GUI half on the spike: the drawer's
  **"What it means here"** section auto-runs per **D1** with its three mitigations (session
  cache · non-blocking · enabled-only). `make check-ci` green.
- **GUI-6 — EDR drafted** (`EDR-GUI-01`, D1–D10 + 4 phases): one deployable that stays a view ·
  named API-key-backed operators (D5 honored) · authenticated inbound edge with a server-side
  session · node key stays server-side · the wiring table as contract · the AI honesty surfaces
  kept first-class · tests/coverage paid · embed+dev-override · queue preview · systemd. Lands
  on its own branch for review; the OpenSpec change scaffolds from it when implementation is
  scheduled.

**Merge order when the time comes:** `feat/knowledge-cve-summary` → retarget + merge
`feat/intelligence-explain` → `feat/knowledge-distro-feeds` (independent) — never
`--delete-branch` the base of the stack.

### CHECKPOINT — end of day 2026-08-12 (RESUME HERE)

**Everything is committed and pushed; no uncommitted work anywhere.** Branch map:

| Branch | Contains | State |
| --- | --- | --- |
| `gui/dashboard-spike` | the GUI (GUI-7/8/9, publication viewer, explain auto-run) + all feature branches merged in | deployed on the VM, live-tested |
| `feat/knowledge-cve-summary` | CVE summary chain (base of the stack) | pushed, no PR |
| `feat/intelligence-explain` | `explain_vulnerability@v1` (stacked on cve-summary) | pushed, `check-ci` green, no PR |
| `feat/knowledge-distro-feeds` | GUI-4 per-distro health rows + GUI-2 Alpine feed + KN-FIX-3 filing | pushed, `check-ci` green, no PR |
| `docs/edr-gui-01` | EDR-GUI-01 (D1–D10, Proposed — awaits the grill) | pushed, no PR |

**Live-verified today:** GUI-7/8/9 + publication viewer (morning round, full pass) · GUI-4
(`osv/rocky` row) · GUI-2 (5 branches fetched, **78 bounds folded in 28s**) · GUI-1 (auto-run
explain with session cache) — all on the VM against real data.

**The day's big find — KN-FIX-3 (MED-HIGH, measured):** fix attribution is ecosystem- and
stream-blind with inconsistent NEVRA normalization. One Rocky perl finding attributed FOUR
fixes: the right EL8 NEVRA, **an Alpine apk version** (`5.30.3-r0` — the cross-ecosystem leak),
an EL7 fix, and the same EL8 fix twice under two normalizations. It rides into AI grounding
(the AI-GROUND-1 class returns). Filed with root cause + fix shape (a `FixedVersion.Ecosystem`
domain change — design before code). The Alpine feed didn't create the defect; it created the
first estate where it was observable.

**VM state to verify on resume:** (a) the Alpine feed was recommended OFF
(`THEMIS_ALPINE_ENABLED=0` + restart) since the estate has no Alpine SBOMs — confirm it
happened; the 78 proposals stay on cards (append-only) and the stray apk fix remains visible in
drawers until KN-FIX-3; (b) confirm the step-5 budget test variables
(`THEMIS_INTELLIGENCE_BUDGET_TOKENS`) were removed from the intelligence env; (c) the dashboard
runs via `nohup` — re-start after any reboot.

**Tomorrow's menu, in rough order of value:**
1. **KN-FIX-3** — the next substantive Knowledge work; design-first (the fix shape is in the
   backlog entry). GUI-2b (apk verdict) is naturally blocked behind it — the ecosystem
   qualifier it needs is the same one.
2. **Open the three PRs** when wanted (merge order above) — explicitly the user's call.
3. **Grill EDR-GUI-01** (say "grill EDR-GUI-01") → OpenSpec scaffold → GUI-6 implementation.
4. Backlog standing items beyond the GUI track: R7 (GOV-15 clamp) and R6 (F5 + rotation)
   remain the highest-priority measured defects outside this line.
