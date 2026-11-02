# EDR-INCIDENT-01 — What Themis does during a vulnerability wave

Status: **PROPOSED — 2026-11-02, awaiting owner acceptance before any code**
Date: 2026-11-02
Author: the beta-readiness discussion of 2026-11-02 (thread "Nessus report intake")

## Purpose

Engineering Decision Record for **how Themis behaves while a wave of vulnerabilities is being
disclosed and the vendor is releasing fixes faster than anyone can read them** — the situation the
owner met during the beta rehearsal: many criticals already open, a burst of new names on top
(a PHP web-shell class, a certificate-authority incident, a run of virtualization-host kernel
CVEs), Red Hat shipping advisories day after day, and nobody able to say for a given host whether
*our* components were among the ones fixed.

The question is not "does Themis know about the CVE". It usually does (OSV distro records,
NVD, the Red Hat vendor feed). The question is the one a security engineer is asked in the
meeting: **"For CVE-X / RHSA-Y — which of our releases are hit, which already have a vendor fix,
and which are proven patched?"** Today Themis holds every fact needed for that answer and shows
none of them together.

## What Themis does today (measured 2026-11-02, code at tag v0.5.0)

1. **A vendor fix is learned, quietly.** When `THEMIS_REDHAT_ENABLED=1`, the Red Hat sweep
   (`THEMIS_REDHAT_POLL_INTERVAL`, default **12h**) folds the advisory's fixed build onto the
   card as a `FixedVersion{Package, Version, Ecosystem}` (EDR-VEX-01 Phase 3). The per-component
   re-judgement then marks each installed occurrence **open, reason "behind"** or clears it
   (EDR-VERDICT-01; `ComponentVerdictChanged` only on a real state change). Governance mirrors the
   state onto its component row. **Nothing tells a person**: no event kind on the webhook / Jira
   / mail routes says "a fix was published for something you have open". The engineer learns it
   by opening the Finding.
2. **With the Red Hat feed OFF (the code default; the beta estate has it ON, checked 2026-11-02)**, the
   fixed build arrives only through OSV's Red Hat ecosystem records, on the next discovery of that
   component (upload or the re-discovery sweep, KN-RECOR-1) — so "fix available" can lag the
   advisory by a day or more, and the vendor's `not_affected` / `will_not_fix` statements are
   never gathered at all.
3. **"Fix available" and "patched" are different facts and Themis keeps them apart — correctly,
   but silently.** The only proof a host was patched is **new evidence**: a new SBOM or a new
   Nessus inventory for that release (EDR-INTAKE-01). Until that upload, the occurrence stays
   open "behind", and nothing reminds anyone that the proof is owed.
4. **The on-demand gather (`POST /faultlines/gather`, G-AI-1) asks NVD only.** Red Hat is not a
   gather source, so an operator cannot pull one advisory's fixed builds now; they wait for the
   12h sweep.
5. **There is no page for "these N CVEs" or "this advisory".** The GUI has one CVE at a time
   (`#/cve/<id>`); `GET /faultlines/{id}/releases` gives release ids, not states. A wave is
   10–40 identifiers that arrive as a list, and the answer is wanted as one table.

Everything that follows adds **surfaces** over facts Themis already records. No new decider, no
new authority: the authority line of EDR-GOVERNANCE-01 stands, and vendor evidence stays Asserted
(EDR-VEX-01 "Gathering Is Not Knowing").

## Decisions

### D1 — A vendor fix published for an open occurrence is an event, delivered on the existing routes (feature A)

Knowledge emits **`knowledge.fix_published.v1`** when a card gains a `FixedVersion` for
`(package, ecosystem)` **and** at least one release holds an open occurrence of that package the
fix would cover (the re-judgement's "behind" set). Payload: card id, CVE, package, ecosystem,
fixed version, advisory id when the source carried one (the Red Hat feed records the RHSA on its `fixed` statement, EDR-VEX-02 D14), and the
list of `{release_id, components_behind}`. Emitted once per `(card, package, ecosystem, fixed
version)` — a restatement by a second source emits nothing (same rule as `ComponentVerdictChanged`).

Governance consumes it and raises **one** `governance.fix_available.v1` per affected release
(release-scoped, like `release_evaluated`), carrying product / project / version names through
the Registry chain so the message reads "Product / Project vVersion". Communication routes it
as webhook event **`fix_available`** (Teams card title "Fix available"), Jira comment on the
release's ticket when one exists, and mail to the configured audience — through
`THEMIS_COMMUNICATION_WEBHOOK_ROUTES` etc. exactly like the five existing kinds. Default route:
none (an operator opts the kind in, as for every other kind).

Why release-scoped and not per CVE: during a wave one RHSA fixes many CVEs in one build; a
message per CVE is the noise the owner described. One message per release says "N CVEs in M
packages now have a vendor fix on this host; nothing is proven until you re-scan".

### D2 — A watch list: identifiers in, one state table out (feature B)

A **Watch** is a named, operator-owned list of identifiers. Accepted inputs, mixed freely:
**CVE ids** and **advisory ids** (RHSA-/RHBA- today; an advisory resolves to its CVE set through
the card's recorded advisory alias — the Red Hat feed already records it on the proposal — and an
advisory Themis has not seen resolves to nothing and says so). A Watch holds: name, created-by,
created-at, the raw identifiers as typed, and the CVE set they resolved to at last evaluation.

`GET /api/v1/watches/{id}/status` (Governance, read scope) returns the **per-(release, CVE)
state**, computed on read from facts already stored — no new truth, so it cannot drift:

| State | Meaning | Source of the fact |
| --- | --- | --- |
| `not_affected` | no component of the release matches, OR a Position `not_affected` stands | Knowledge match table · Governance Position |
| `open_no_fix` | occurrence open, no vendor fix known for its package/ecosystem | occurrence verdict + `FixesFor` empty |
| `open_fix_available` | occurrence open "behind", a fix is recorded | occurrence verdict reason + `FixedVersion` |
| `fixed` | occurrence cleared by evidence newer than the fix | occurrence verdict cleared, evidence `filed_at` > fix learned at |
| `accepted` | a Position `accepted_risk` / `mitigated` / `deferred` stands | Governance Position |
| `unknown` | CVE has no card, or the advisory resolved to nothing | — |

Plus per release: newest evidence `filed_at` and kind, so the table shows "last proof: Nessus
inventory 2026-10-29". The GUI gets a **Watches** page: paste identifiers, name it, see the table,
one row per (release, CVE), filter by state, export CSV. A Watch is append-only on its identifiers
(you can add, never silently drop) and deletable as a whole.

Optional (D2a): when a Watch is marked `notify`, a state change of any of its rows between two
evaluations (evaluation runs on every `release_evaluated` and `fix_available`) emits
`governance.watch_changed.v1`, routed as webhook kind **`watch_changed`**. Off by default.

Why Governance owns the Watch: it is the context that already joins Knowledge's verdicts with
Positions and Registry names (the posture projection). The Watch reads the same seams; nothing new
crosses a context boundary.

### D3 — A fix known for N days with no newer evidence owes a reminder (feature C)

A release with at least one `open_fix_available` row whose fix was learned ≥ `THEMIS_RESCAN_AFTER`
(Go duration, default **168h** = 7 days) ago, and whose newest evidence is older than that fix,
gets **one** `governance.rescan_due.v1`, routed as webhook / mail kind **`rescan_due`** ("Fix known
7 days, no new scan for Product / Project vVersion"). Re-issued every `THEMIS_RESCAN_AFTER` while
the condition holds, never more often. New evidence for the release clears the condition.

This is the review-by sweep's shape (EDR-REMEDIATION-01 D2, `THEMIS_REVIEW_BY_INTERVAL`) applied
to a different premise; it reuses that worker. It changes no Finding and no Position.

### D4 — Red Hat is a gather source, and the sweep interval is an incident knob

`POST /faultlines/gather` consults the Red Hat per-CVE source beside NVD whenever a Red Hat base
URL is configured, so an operator (or the Watches page's "Gather now" button, one call per CVE
in the Watch) pulls today's advisory bounds **now**. The sweep stays as it is;
`deploy/node.env.example` documents **`THEMIS_REDHAT_POLL_INTERVAL=1h` as the incident setting**
(Red Hat's security-data API is rate-tolerant at that cadence; the sweep is relevance-bounded,
EDR-KNOWLEDGE-01 D5, so it touches only cards that exist).

### D5 — Limits stated on the page, not hidden

The Watches page and every `fix_available` / `rescan_due` message carry the sentence: **"Fix
available is the vendor's statement. Patched is proven only by a new scan or SBOM of this
release."** Themis never infers a patch from time passed or from an advisory existing.

## Order of work (owner-agreed 2026-11-02: A → B → C)

| Step | Scope | Touches |
| --- | --- | --- |
| **A** (D1 + D4) | `fix_published` event, Governance consumer + `fix_available` event, Communication kind + Teams title, Red Hat gather source, env docs | Knowledge app/domain/adapters, Governance consumer, Communication delivery, `node.env.example`, user guide |
| **B** (D2, D2a) | Watch aggregate + store + migration, status projection, API in `api/governance.openapi.yaml`, GUI page, optional `watch_changed` | Governance domain/app/adapters/store, dashboard |
| **C** (D3) | `rescan_due` on the review-by worker, `THEMIS_RESCAN_AFTER`, Communication kind | Governance app, Communication delivery, env docs |

Each step: OpenSpec change `phase3-incident-<step>`, `make check-ci` green, VM-verified with a
scripted scenario (upload SBOM → gather a CVE whose advisory is newer than the SBOM → message
arrives → re-upload patched inventory → row turns `fixed`). Step A is a **beta-period change**;
per the 2026-10-28 freeze it ships only with the owner's explicit go.

## What this record does NOT decide

- Automatic acceptance of anything. A `fixed` row is a display state; the Finding closes through
  the existing evidence-driven path, not because a Watch said so.
- Multi-vendor advisories (Ubuntu USN, Debian DSA): the advisory → CVE resolution uses whatever
  alias the card carries; feeds that do not record one resolve to `unknown` until they do.
- Re-classifying the open "behind" wording (KN-OPEN-REASON-1) — unchanged.
