# Tasks — phase3-intelligence-d2 · Δ2 (typed dispatch + Rule Engine + admission spine)

> **Scope: Δ2 only** — grow the Δ1 walking skeleton into the harness's typed multi-engine shape **on the same
> seams (additive, no rewrite)**, grounded in `docs/engineering/decisions/EDR-INTELLIGENCE-01.md` **Revision 3**
> (Δ2 concrete cut) with grounded component choices **C1–C7**. Out of scope: Python engine + RAG (Δ3),
> autonomy + LLMOps (Δ4), and the deferrals **G-AI-1..5** (`PHASE3-BACKLOG.md` §C). Each group ends with the
> six Themis gates (`make check`), extended to the new packages. Δ2 adds **no new third-party dependency** and
> **no datastore**.

## 1. Version-range value object in the shared kernel (C2)

- [x] 1.1 Add a **version-range applicability** value object under `internal/kernel/value/` — **ported by
  design** from the PoC version engine (`internal/domain/version_engine.go` + `version_match.go`), **not
  imported** (PoC is frozen reference). Cover the ecosystems the PoC handles (SemVer, PyPI, Alpine `-r0`,
  introduced/fixed/last_affected, GIT-vs-ECOSYSTEM) and expose a total result: `outOfRange` / `inRange` /
  `undecidable` (unknown/unsupported ecosystem or missing range).
- [x] 1.2 **Rapid property test** carried from the PoC's proven property test (monotonic comparison; a version
  never both in- and out-of-range; unknown ecosystem → `undecidable`, never a false certainty).
- [x] 1.3 Unit tests to 100% (kernel value is a leaf, pure). Register the package in the coverage tiers
  (`scripts/check-coverage.sh` and Makefile `COVERAGE_PKGS`).
- [x] 1.4 Gate: build + clean-arch (`TestKernelIsLeaf` still holds) + coverage green.

## 2. Rule Engine — version-range applicability (C3 · all-Go, behind the Engine port)

- [x] 2.1 `internal/intelligence/domain`: a **Rule engine** as **hand-written Go predicates** (no DSL/engine)
  using the kernel version-range value object. The version-range rule reads the **reconciled** range from
  grounding (`FaultlineView.AffectedRanges`) and the matched component's **ecosystem + version from its PURL**
  (`value.PURL`), builds a `value.AffectedRange`, and maps `Applicability`: `RangeOutOfRange` → certain
  **`not_affected`**; `RangeInRange` → **defer to LLM** (never auto-`affected`); `RangeUndecidable` →
  **defer**. Certain in **one direction only**. It checks the reconciled/backport-aware range, **not** a
  re-run of the feed's query-time filter (see EDR Rev 3). A withdrawn-CVE rule was **rejected** (would
  duplicate Governance's `proposalFor`). A Finding decides `not_affected` only if **every** matched component
  is provably out of range; any in-range/undecidable component → defer.
- [x] 2.2 Expose the rule behind the existing **Engine port** (`Engine.Execute(step, ctx) → RawResult`) as a
  Rule engine adapter (`adapters/engine`), alongside the Δ1 LLM engine — one more Engine, same port.
- [x] 2.3 Unit tests to 100%: out-of-range short-circuits to `not_affected`; in-range defers; undecidable
  defers; **never emits `affected`**. Hermetic, no provider.
- [x] 2.4 Gate: six Themis gates green.

## 3. Engine Dispatcher + two-step `[Rule → LLM]` plan + provenance (C4)

- [x] 3.1 `internal/intelligence/app`: a **small in-Go typed Engine Dispatcher** routing an ExecutionPlan
  step's engine-kind → the registered Engine (Rule or LLM). No workflow engine, no plugins.
- [x] 3.2 Grow `recommend_position`'s ExecutionPlan from `[LLM]` to **`[Rule → LLM]`**: run the Rule step
  first; **if it decides (`not_affected`), short-circuit** — no dispatch to the LLM, no grounding, no provider,
  no admission gate; else continue to the LLM step (Δ1 pipeline unchanged).
- [x] 3.3 **Provenance stamp** on every result: `rule:not_affected` / `llm:<stance>` / `insufficient` — carried
  in the Proposal envelope metadata (the testability hook + the G-AI-2 metric source).
- [x] 3.4 Tests: `outOfRange` → decided by **rule**, **provider never called** (assert via a spy provider);
  `inRange` → routed to the LLM; provenance stamp correct on each path.
- [x] 3.5 Gate: six Themis gates green.

## 4. Honest `insufficient` outcome (first-class, non-error)

- [x] 4.1 Extend the **recommendable set** to `{affected, not_affected, mitigated, insufficient}`; `insufficient`
  = "can't determine — no recommendation". Update the capability output schema (jsonschema) + the business
  validator to accept it.
- [x] 4.2 Wire `insufficient` as a **non-error terminal outcome** of the plan (no facts / rule undecidable +
  LLM declines) — distinct from the disable-gate "no proposal" (which is AI-off/unavailable), and never a
  validation failure.
- [x] 4.3 Tests: no grounding → `insufficient`; LLM low-confidence/decline → `insufficient`; `insufficient` is
  recorded with provenance, never raised as an error.
- [x] 4.4 Gate: six Themis gates green.

## 5. Richer grounding — precedent Positions (C6)

- [x] 5.1 **Governance read-API**: add a "**Enterprise Positions for this CVE across releases**" query to
  `api/governance.openapi.yaml` (+ oapi-codegen + handler + projection/read model). Read-only.
- [x] 5.2 Intelligence **`PrecedentReader` port** + a Governance read-API **client adapter** (mirrors the Δ1
  `FindingReader`/`FaultlineReader` seam), fakeable.
- [x] 5.3 Context Construction: **only when the plan reaches the LLM step**, pull past Positions on the same
  CVE and add them to `AssembledContext` **labeled** (release, component version, decision, rationale) as
  **context, not instruction**. Ranking by release-delta is **G-AI-3** (out of scope).
- [x] 5.4 Tests: precedent present → appears labeled in `AssembledContext` and in the prompt input; precedent
  absent → grounding still valid; rule short-circuit path pulls **no** precedent (no wasted read).
- [x] 5.5 Gate: six Themis gates green (Governance + Intelligence packages).

## 6. Admission gate — budget meter + runaway guard (C5 · measure now, enforce later)

- [x] 6.1 One **pre-invocation admission gate** in `app`, run **before any provider call** (the rule step is
  not gated). Δ2 = a **meter** (per-call duration / input-size / token count) via **OpenTelemetry metrics**
  (`internal/platform/observability`) + one **runaway guard** (per-request timeout + prompt input-size cap).
- [x] 6.2 Real multi-scope budget **enforcement** (4 scopes) + degrade-not-fail model-downgrade is **NOT built**
  — deferred to **G-AI-4**; leave a documented seam, not a stub with behavior.
- [x] 6.3 Tests: meter emits the fields on every LLM invocation; runaway guard trips on oversize input /
  timeout → `insufficient` (never a hang or a crash); rule short-circuit path emits no provider meter.
- [x] 6.4 Gate: six Themis gates green.

## 7. Admission gate — security/privacy (C7 · minimal, local-only)

- [x] 7.1 In the same gate: (1) **authorize** the caller/capability request; (2) a **`Redactor` port**
  (mirrors Communication) scrubs secrets/PII from the prompt **and** telemetry; (3) **hard-mark the path
  local-only** so nothing can reach a cloud provider.
- [x] 7.2 Full **data-classification → provider-clearance** admission is **NOT built** — deferred to
  **G-AI-5** (arrives with cloud providers); leave a documented seam.
- [x] 7.3 Tests: unauthorized caller → rejected before any provider call; secrets/PII redacted from prompt +
  telemetry (golden); local-only flag set on the provider binding.
- [x] 7.4 Gate: six Themis gates green.

## 8. Governance caller — handle `insufficient` + provenance (no auto-accept)

- [x] 8.1 Update `internal/governance/adapters/intelligence` + the "recommend a position" action to handle the
  four outcomes: a stance proposal (`affected`/`not_affected`/`mitigated`) is recorded as an **ai** Governance
  Proposal (as in Δ1); **`insufficient`** records **no proposal** (honest non-answer surfaced to the human),
  never an error.
- [x] 8.2 Carry the **provenance stamp** (which step decided) into the recorded proposal's rationale/metadata;
  **never auto-accepted** (human decides) — unchanged from Δ1. Structured proposal columns remain the deferred
  follow-up (backlog).
- [x] 8.3 Tests: rule-decided `not_affected` → ai-proposal with `rule:not_affected` provenance; LLM-decided →
  `llm:<stance>`; `insufficient` → no proposal, pipeline unchanged; AI-off (no-op) still zero calls.
- [x] 8.4 Gate: six Themis gates green.

## 9. Δ2 seam e2e + docs

- [x] 9.1 Intelligence per-context e2e (own reactive API + fake provider + fake read-APIs): out-of-range →
  rule-decided `not_affected` (**provider never called**); in-range → LLM path → validated Proposal;
  no-facts → `insufficient`; disabled → no-op.
- [x] 9.2 Governance→Intelligence seam test (httptest): the exact wire JSON for each of the four outcomes +
  the provenance stamp; ai-proposal recorded for stance outcomes, none for `insufficient`.
- [x] 9.3 Update `docs/engineering/PHASE3-STATUS.md` (Δ2 done, Δ3–Δ4 remain), `PHASE3-BACKLOG.md` (mark the
  §A Δ2 line, keep G-AI-1..5 open), and `openspec/STATUS.md`.
- [x] 9.4 Gate: six Themis gates green; `markdownlint-cli2` clean.
