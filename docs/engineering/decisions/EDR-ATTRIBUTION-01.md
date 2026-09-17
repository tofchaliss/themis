# EDR-ATTRIBUTION-01 — The carrier attribution gap (the backlog's "EDR-3")

Status: **Accepted — specification 2026-09-17.** The design this replaces was agreed in principle on
2026-09-16 and **invalidated by measurement on 2026-09-17**, before any code was written. That sequence is
the point: the premise was checked against the estate and did not survive.
Date: 2026-09-17
Author: the httpd/claim-class arc → the EDR-3 measurement session

## Purpose

Engineering Decision Record for what it MEANS when a Faultline's carrier products match none of the
components recorded against it.

The governing sentence, and everything below follows from it:

> **Zero match is an OBSERVATION, not an identity conclusion.**

## What the measurement decided (and what it killed)

The agreed design was: *when carriers are known but none relates to any component on the card, classify
`unknown` rather than `scope`* — "the UNKNOWN rule". It rested on a recorded claim that the python
module-stream cluster was protected, because `python3` on those same cards would match and make them
partial rather than whole-card misses.

**That claim is false.** Measured 2026-09-17 on MRF, post-retirement — the all-scope findings are:

| component | rows | correct class |
| --- | --- | --- |
| `python3-pyyaml` | 116 | **`scope` — correct** |
| `httpd` | 87 | `scope` — **wrong**, it is the carrier under another name |
| `python3-ply` | 66 | **`scope` — correct** |
| a ~6-each `perl-*` cluster, `javapackages-filesystem` | ~90 | mixed |

**The decisive case.** Finding `a3c6e965`, card `a8676695`, **CVE-2023-32681 — the `requests`
proxy-authorization leak.** Its only components are `python3-ply` and `python3-pyyaml`, both `scope`. There
is **no `python3-requests`** on the release: the estate has the rebuilt stream members installed and not
the package that carries the flaw. So every component on that card is a **legitimate bystander**, and
`scope` is right for both.

**Two situations, one observable condition, opposite correct outcomes:**

| | carriers | matches | correct outcome |
| --- | --- | --- | --- |
| `http_server` vs `httpd` | known | zero | the carrier IS installed, under another name |
| `requests` vs `pyyaml`/`ply` | known | zero | the carrier is genuinely NOT installed |

The UNKNOWN rule cannot tell them apart, because telling them apart IS the synonym question. It would
have broken **182 correct suppressions to fix 87 wrong ones** — re-opening precisely the module-stream
false positives EDR-CORRELATION-01 exists to prevent. **REJECTED on evidence.**

## Realizes (ADR/EDR traceability)

- **EDR-CORRELATION-01 D3** — the `carrier`/`scope`/unknown vocabulary is **unchanged**. This EDR adds an
  observation ABOUT a card's attribution, not a fourth class.
- **EDR-IDENTITY-01 D9** — that EDR owns whether an identity can be ESTABLISHED and hands the
  *meaning of failure* here. This is that answer: failure means a gap, not a verdict.
- **EDR-VERDICT-01 D2** — "checked and fine" must be distinguishable from "never looked". The same
  principle, one level up: *"attributed and unmatched"* must be distinguishable from *"we cannot attribute
  at all"*.
- **Domain Invariant 3 ("Gathering Is Not Knowing")** — a gap is gathered information about the limits of
  what was gathered. It asserts nothing about the world.

## Decisions

### D1 — The Attribution Gap is a state, and it is NOT a verdict

    carrier attribution gap  =  carriers exist  +  zero deterministic component matches

It says exactly one thing: **"Themis has insufficient identity evidence to attribute this carrier to an
installed component."**

It says **nothing** about whether any component is affected. It is not a severity, not a stance, not a
claim class, and nothing may treat it as one. The `requests` case proves why: zero correlation cannot by
itself mean affected, unaffected, or bystander.

### D2 — The gap must NOT be expressed as `unknown`

`unknown` already means something precise and different: *this component is treated as affected, its
attribution evidence is missing, and it therefore acts as a carrier* (EDR-CORRELATION-01 D3). Overloading
it with *"we cannot attribute this carrier to anything installed"* would give one value two meanings, and
every consumer would then have to guess which one it holds. **Two different statements, two different
places to record them.**

### D3 — The gap is DERIVED, not stored

`ClassifyClaim` returns `scope` **only** when the carrier set is non-empty and the component matched none
of it. Therefore, for a Finding whose components were classified against one carrier set:

    every active component is `scope`   ⟺   carriers exist + zero matches

So the gap needs **no column, no event, no migration** — it is a read-model derivation over data both
contexts already hold. Governance can compute it without knowing the carrier set at all.

**Its one precondition is classification currency**, which the re-classification sweep (KN-CLAIM-1,
shipped 2026-09-17) now provides: before that sweep, two components of one Finding could carry classes
stamped against different carrier sets, and the equivalence would not hold.

### D4 — The 182 module-stream bystanders keep `scope`

Their current classification is **supported by the evidence measured**. They are not reclassified to make
the system look conservative; conservatism that contradicts measured evidence is not caution, it is noise
that costs an operator 182 re-opened findings.

### D5 — The 87 httpd cases stay UNCHANGED until identity evidence exists

They are wrong today: `http_server` and `httpd` are the same software, and `scope` understates them. But
the fix requires evidence Themis does not currently hold, and **no rule available now can separate them
from D4's cases.** They are surfaced (D6), not reclassified.

### D6 — Surfacing is the deliverable, and it is what recovers the measured cost

The gap SHALL be exposed as a countable, visible state. The specific measured cost it recovers: of the 87
httpd components, **74 are `cleared_vendor_fix`** — verified clearances invisible to the GUI's cleared
tile, because that tile requires `carriers.length > 0`. Surfacing the gap lets the tile present them
**without asserting that any component carries the flaw**.

Honest in both directions, which is the whole point: the operator sees "74 verified clearances on cards
whose carrier we could not attribute", not "74 carriers".

### D7 — CPE is an evidence-ACQUISITION experiment, not the solution

The measured absence of CPE in the estate's SBOM is a property of **how that artifact was generated**, not
proof that CPE cannot exist. Syft can emit `cpe23Type` external refs. If it does, then
`cpe:2.3:a:apache:http_server` beside `pkg:rpm/rocky/httpd` makes the synonym **deterministic** — no
Themis-maintained synonym dictionary, which is the line every reviewer of this arc has refused to cross.

**It is not accepted as the answer.** Six preconditions must ALL hold before CPE becomes an
identity mechanism in Themis:

1. Syft emits the expected CPE for `httpd`.
2. The CPE survives the SBOM parser.
3. Themis retains it through the identity path.
4. NVD's CPE representation normalizes to the same identity.
5. The relationship holds for more than httpd.
6. A missing or wrong CPE fails SAFE rather than creating a false match.

### D8 — Do not declare an identity hierarchy yet

`PURL → CPE → metadata → name` is **not** written as a normative hierarchy by this EDR. It is a
hypothesis until D7's six preconditions are measured. Declaring it now would repeat the mistake
this EDR exists to correct: encoding an invariant ahead of its evidence.

## Validation criterion

1. The gap is countable and visible, and equals the all-scope Finding population (227 measured).
2. The 74 cleared httpd components become visible WITHOUT any component's class changing.
3. `python3-pyyaml` (116) and `python3-ply` (66) keep `scope` — the guard this EDR exists to protect.
4. No component anywhere is classified `unknown` by a gap.

## Phases

- **A — specify the Attribution Gap** (this document).
- **B — the CPE experiment:** regenerate ONE SBOM with CPE external refs and measure whether httpd
  carries its Apache CPE. Read-only; changes nothing.
- **C — trace CPE end to end** if B succeeds, against D7's six preconditions.
- **D — only then** decide whether CPE belongs in the canonical identity model.

## Honest limits

- **The 87 httpd cases remain misclassified** for as long as this EDR stands alone. That is a stated cost,
  not an oversight: the alternative breaks 182 correct answers.
- **The gap derivation depends on classification currency.** If the re-classification sweep stops running,
  the equivalence in D3 silently weakens. That coupling is real and belongs in whatever surfaces the gap.
- **`perl-*` and `javapackages-filesystem` in the all-scope population are a MIXED set** — some genuine
  bystanders, some vocabulary failures — and this EDR does not separate them either. Same reason.
