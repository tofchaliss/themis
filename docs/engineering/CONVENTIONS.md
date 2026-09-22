# Phase-3 Greenfield — Cross-Cutting Engineering Rules

**Updated:** 2026-07-15 · **Read with `STACK.md` before any `/opsx:apply`.** These are rules **every node**
(each deployable context/service — Registry, Evidence, Knowledge, Governance, Communication, Intelligence)
follows, independent of any single OpenSpec change. They are not per-change tasks; they are standing
conventions. **ADR wins.** New cross-cutting rules are added here (R1, R2, …).

## R1 — Every node logs to the console AND to OpenTelemetry

Dual observability, always on. **Each node emits both**, wired identically from one shared observability
package (never per-context bespoke logging):

- **Console** — structured logs to stdout via **`zap`**; human-readable in dev, JSON in prod. This is the
  **local-debug** channel.
- **OpenTelemetry** — traces + metrics + logs to the configured OTel exporter. This is the **architectural
  telemetry**, correlated by **stable business identifiers** (not infra ids).

Rules:

- Both channels are available in **every environment**; which exporters are active is **config-driven**
  (R2). Console is the local-debug artifact; OTel is the telemetry system-of-record — BCK-0051 explicitly
  distinguishes debug logs from architectural telemetry.
- **No raw `fmt.Print*` / ad-hoc printf as telemetry.** All output goes through the structured logger.
- **Redact before emitting** — secrets, PII, and confidential enterprise data never appear in the clear in
  either channel (INT-0064/0069).
- Every significant operation carries a **correlation id** so a workflow can be reconstructed across nodes
  (BCK-0051).

Grounded in **BCK-0051** (observability = architectural capability: structured logs + metrics + traces +
correlation ids) and **INT-0064**; consistent with `EDR-INTELLIGENCE-01` D9 (OpenTelemetry + console
debug), generalized to all nodes.

**Realized by `internal/platform/observability`** (2026-07-18): one `Setup(ctx, Config)` builds a **zap**
logger whose core **tees** to stdout (console/JSON) **and** an OTel `LoggerProvider` via the `otelzap`
bridge — a single `log.Info(…)` emits a console line **and** an OpenTelemetry log record. The level, console
format, and OTLP endpoint are read by `ConfigFromEnv` (`THEMIS_LOG_LEVEL` / `THEMIS_LOG_FORMAT` /
`THEMIS_OTLP_ENDPOINT` — `THEMIS_OTLP_LOGS_ENDPOINT` still honored as a fallback — / `THEMIS_OTLP_INSECURE`);
OTel export is on only when an endpoint is set. A `RequestLogger` middleware logs every HTTP request with a
correlation id.

**All three signals are now live (2026-08-07).** Metrics (2026-08-06) are a Prometheus registry scraped at
`/metrics`; **traces** are an OTLP `TracerProvider` with a server span per HTTP request. Two deliberate
choices:

- **The span is named after the route pattern, not the raw path** — `GET /api/v1/findings/{id}`, not one
  span name per finding id. Because chi only fills its `RouteContext` *during* routing, the middleware names
  the span provisionally and **renames it after the handler returns**; naming it up front would have
  produced `GET other` for every request.
- **Every span carries `themis.correlation_id`**, the same id the log line carries — that shared key is what
  makes a trace and its logs joinable. A trace without it is a latency chart; with it, it is an
  investigation.

**Metrics are pull, traces are push**, on purpose: a counter survives having no collector (it accumulates
until someone scrapes) while a span does not (it has no pull model), so metrics stay useful on an isolated
node and traces cost one exporter dependency rather than two. The pure `domain`/`app` rings never
log (enforced by depguard — only adapters + the composition root import the package), so the package sits at
the platform layer, outside any bounded context. **All six** greenfield nodes
(`cmd/{registry,evidence,knowledge,governance,communication,intelligence}`) wire it at startup and each
mounts `/metrics`; example config in `deploy/node.env.example`.

## R2 — Configuration is self-documented in the config file, with comments

Configuration documentation lives **in the config file itself**, as inline comments — there is **no
separate config reference doc** that can drift out of sync.

Rules:

- **Every option carries an inline comment** stating: what it controls, its type + units, the **default**,
  and valid values / range.
- Each node ships a **fully-commented example config** (e.g. `config.example.yaml` and/or `.env.example`)
  covering **all** of its options — e.g. DB DSN, HTTP address, **OTel exporter endpoint + on/off**, **log
  level + format** (R1), plus node-specific options (Intelligence budget/pool sizes + provider clearance;
  Knowledge feed endpoints; Communication channels; etc.).
- **Secrets are referenced, never inlined** — the example names the env var (or secret ref), never a real
  value.
- The commented example config is the artifact a reviewer reads to understand every knob; keep it current
  as options are added.

## R3 — Aggregate reads inside an event handler join the ambient inbox transaction

An inbound event handler runs its writes inside the consumer **inbox unit of work** (the exactly-once
transaction, EB-06). Any aggregate **read** it performs — including the re-load in an optimistic
load-apply-save retry — **must run on that same transaction**, not on the pool. Route reads through the
store's `querier(ctx)` seam (returns the ambient tx when one rides the context, else the pool); the write
seam is `Save` / `exec(ctx)`.

**Why:** when one envelope mutates the *same* aggregate more than once (e.g. a `faultline_enriched` that
both re-prioritizes and folds a VEX applicability onto one Finding), a committed pool-read cannot see the
first mutate's uncommitted version bump, so the optimistic `WHERE version = prev` matches zero rows and
`ErrConcurrent` **never converges** — the reader poison-halts the whole stream (D8). This is the third
symptom of one root tension — the D7 correlation-tx stall, the PR #59 Knowledge shared-CVE halt, and the
Governance enrichment halt (BUG-1). Treat "handler reads on the pool" as a defect.

**Guard:** each context's store owns a regression test that mutates one aggregate twice within a single
inbox envelope and asserts convergence (e.g. Governance's `TestInboxTwoMutationsOnOneFindingConverge`).

## R4 — Measure a rule's TRIGGERING PREDICATE against the estate before encoding it

A design can be logically sound, feel conservative, and still be wrong — because its trigger collapses
distinct real-world cases that require opposite outcomes. Reason about the rule all you like; the thing to
go and measure is **what fires it**.

**The measured case (2026-09-17, EDR-ATTRIBUTION-01).** The proposed rule was "carriers known, nothing
matched ⇒ classify `unknown`", which fails toward treating a component as affected and therefore *reads*
as the safe direction. Its trigger — a whole-card match miss — turned out to cover two situations that are
indistinguishable in the data and opposite in truth:

| observable | reality | correct outcome |
| --- | --- | --- |
| carriers known, zero matches | `http_server` IS `httpd` under another name | treat as carrier |
| carriers known, zero matches | `requests` genuinely not installed; `pyyaml`/`ply` are bystanders | keep `scope` |

It would have broken **182 correct suppressions to fix 87 wrong ones**. One query against the estate found
it, before any code existed. The rule had already been agreed in principle by two people, and it rested on
a recorded claim about a specific cluster (*"`python3` matches on those cards"*) that was simply false.

**How to apply.** Before implementing a rule that classifies, suppresses, or re-opens anything:

1. Write down the predicate that fires it, on its own.
2. Query the estate for the population that predicate selects — not the population you have in mind.
3. Inspect a concrete member of that population end to end, including the ones you expect to be excluded.
4. If the predicate selects cases requiring opposite outcomes, the rule is **unsound, not mis-scoped** —
   do not rescope it, and do not add conservatism on top. Find a different discriminator, or record an
   honest observation instead of a conclusion.

**Corollary, and the sentence worth keeping:** *an observation is not a conclusion.* Where no
deterministic discriminator exists, surface the ambiguity as a first-class, countable state rather than
resolving it by policy. EDR-ATTRIBUTION-01's Attribution Gap is the worked example.

### R4b — Presence of a data field is not presence of useful evidence

The rule has two parts, and the second is the one that gets skipped:

1. Does the evidence **exist**?
2. Does it **contain the information the decision predicate needs**?

**The measured case (2026-09-17, ATTR-CPE-1).** An EDR recorded "the document carries no CPE", generalized
from an observation about two specific packages. The estate turned out to hold **6384 `cpe23Type`
references**. But the finding that mattered was not the correction — it was that those CPEs are generated
heuristically **from the package name**, so `httpd` yields `cpe:2.3:a:httpd:httpd:…`, never
`apache:http_server`. The field was abundantly present and carried **zero independent identity
information**:

    package name → Syft heuristic → CPE → the same vocabulary

rather than the chain the design needed:

    package identity → authoritative CPE → NVD CPE → deterministic bridge

So the experiment answered its question by failing, and it failed for a better reason than absence would
have given: a derived value cannot be independent evidence about the thing it was derived from.

**How to apply.** When a design turns on some field being available, do not stop at "the field is
populated". Ask where its value CAME FROM. If it was derived from the same input the decision is already
using, it adds nothing no matter how many rows carry it.

### R4c — The population you measured may be the output of a DEFECT, not of the domain

R4 says to measure a rule's trigger before encoding it. This is the trap one level in: you measure
the trigger, find a real population, and encode a rule for it — and the population exists only
because something else is broken. Fix that, and the justification evaporates.

**The measured case (2026-09-21, EDR-VEX-02 D11 and D12, three hours apart).** A cleanup run
surfaced three statements answering `unknown` where the vendor had named an unambiguous product:

    spring-web → "Red Hat build of Apache Camel 4 for Quarkus 3"   [unknown × 6]

That was read as evidence for a missing semantic distinction, and a fourth state
(`not_comparable`) was designed and shipped for it. The reading was correct as far as it went. But
the three rows were **produced by a second defect** — the release scope was being read from one
Finding's matched components, so a Java Finding on a release with 688 of 721 rpm components could
place nothing at all. With that fixed, all three resolved to `not_applicable`, and a census found
**every release on the estate resolves cleanly**. The new state has zero reachable instances.

The design survives on semantic grounds — the two words do mean different things — but **the
measurement that justified it was a symptom, and the same three rows were used to justify two
separate issues, only one of which was real.**

**How to apply.** When a measurement is about to justify a design:

1. Ask what PRODUCED each member of the population, not just how many there are.
2. Inspect one member end to end, through the code that generated its value — R4's step 3, aimed
   at provenance rather than at the data.
3. If the population is uniform in a suspicious way (here: six identical verdicts on one Finding,
   because one resolution failed once), treat the uniformity as a clue that ONE upstream fact is
   responsible, not N independent cases.
4. Where a design is right on principle but its measured basis dissolves, **say so in the record**
   rather than leaving the original numbers standing as though they still support it.

**Corollary:** a defect-generated population is the most persuasive kind, because it is real,
reproducible, and points somewhere plausible. Agreement with the data is not evidence about the
cause.

## R5 — A change that alters CARDINALITY must have its invariants and tests re-derived

Elevated to a convention 2026-09-21 by the user, after two defects in one day that a green test
suite could not see: *"Whenever a change alters cardinality, re-derive the cardinality invariants
and tests. Do not merely rerun the existing test suite."*

**Why re-running is not enough.** The existing tests were written against the OLD cardinality, so
they cannot contain the case the change just created. They pass, and their passing means nothing
about the new shape.

**The measured case (2026-09-21, `DEF_VEX_COVERING_FIRST_MATCH`).** A dedup key gained a field, so
one package went from carrying **exactly one** vendor statement to carrying **N**. Downstream,
selection was "take the first match" — correct and harmless while N was always 1. With N > 1 the
statements sorted by scope, the lower major came first, and a Rocky 8.10 release lost the RHEL 8
statement that applied to it because the RHEL 7 statement in front of it was correctly judged
inapplicable.

Two individually correct transformations composing into a false negative:

    keep every product       (correct)
          +
    block what cannot apply  (correct)
          +
    first-match selection    (correct only at N = 1)
          =
    0 proposals raised where 1 was owed

**No test failed.** The suite covered one applicable statement and one inapplicable statement. The
defect lives only in the interaction of two statements for one package — a case that **could not
exist** before the change that created it. It was found by reading D7's own text, which had already
named the requirement, and noticing only its first half had shipped.

**The review questions.** For any change that alters how many of something can exist:

1. What cardinality did the surrounding code **assume**?
2. What cardinality can the new code now **produce**?
3. What happens at **0, 1, and more-than-1** — for every consumer, not just the one being changed?

Question 3 is the one that catches this class, because the dangerous case is almost always the jump
from 1 to many, and the code that breaks is usually code the change did not touch.

**This is a design-review obligation, not a testing technique.** It belongs in the discussion
before implementation, because the tests that would catch it are precisely the tests nobody has
written yet.

**The pattern already has a history in this repository**, which is why it is a rule rather than a
note. Every one of these was a cardinality change that outran its invariants: scanner observations
with no purl, VEX statement deduplication, carrier extraction, `relatedProduct`, and proposal
identity — the last of which is **still open**, because a proposal id keyed on `(finding, package)`
cannot represent N product-scoped statements for one package.

**Related:** R4 measures a rule's trigger; this measures a change's *shape*. A rule can have a
perfectly sound trigger and still break because the data around it changed multiplicity.

## R6 — A plausible mechanism is not a root cause until PERSISTED STATE rules out its rivals

Elevated to a convention 2026-09-22 by the user, from a measured mistake in the same session that
produced R4c and R5: *"Never promote a plausible mechanism to root cause until persisted state
distinguishes it from competing explanations."*

**The forensic order is fixed, and reading code is the LAST step, not the first:**

    observation
        ↓
    stored state            what is actually recorded?
        ↓
    provenance / generation  which rule wrote it, and when?
        ↓
    code                     what could produce that?
        ↓
    explanation

The tempting order — observation → read code → invent explanation — reliably produces an answer,
because a large codebase always contains SOME path that would produce the symptom. Finding one
feels like diagnosis and is not: it is constructing a hypothesis and then declining to test it.

**The measured case (2026-09-22, `DEF_GOV_STAMPED_FIXES_NEVER_REDERIVE`).** A drawer advertised
an `el9` and an `el10` fix for an `el8` install. Reading the code found a real path that would do
exactly that — the EL-stream guard sat behind the fix DECLARING an ecosystem, and the enrichment
signal's `Ecosystem` field is additive, so an older payload would skip the check. Plausible,
consistent with the symptom, and **wrong**: one `SELECT` showed the stored rows carry
`"Ecosystem": "rpm"`, and the release-major parser handles every string involved. With the label
present, the old code would have excluded them. The true cause was that the value was **stamped
before the rule existed and is never re-derived** — invisible in the code path and obvious in the
row.

The defect was filed, committed and pushed with the invented explanation before the query ran.
Both entries are kept in `BACKLOG.md`, the wrong one corrected in place rather than deleted.

**What the rule asks for, concretely.** Before writing "the cause is X":

1. read the stored row, not the code that writes it;
2. ask what ELSE would produce the same row — stale data and a wrong rule look identical from the
   symptom, and only provenance separates them;
3. name the observation that would falsify X, and make it.

**Why this repo in particular.** Themis materializes derived state across context boundaries by
design (`base_score`, `band`, `selected_fixes`, `signal_*`), so at any moment a stored value may
have been written by a rule that no longer exists. In a system like this, "the code does Y"
answers what happens NEXT time, never what happened to the row in front of you. Sibling of R4/R4c
(measure the predicate before encoding it) and of R5 (re-derive, do not re-run): all three are the
same discipline — **check the estate before believing yourself.**

## How these apply per node

Both rules are **shared infrastructure**, not re-implemented per context: one observability bootstrap
package (R1) and one config-loading convention (R2) that every node imports. A node's `main`/bootstrap
wires the shared logger + OTel from its commented config at startup, before serving.
