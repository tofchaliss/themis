# Design — phase3-component-identity

Source of truth: `docs/engineering/decisions/EDR-IDENTITY-01.md` (D1–D9). This file records only the
mechanical choices the EDR leaves open, and the two constraints discovered while reading the seam.

## 1. Where resolution happens, and why not the ACL

**In the app ring (`ScannerReportService.PlanIngest`), not in the scanner ACL.**

The ACL (`adapters/evidence/scanner_source.go`) reads one document and translates it. Twin resolution
needs the *release's* component set, which is a different document — so doing it in the ACL would mean a
cross-document read from a translation seam. The app ring already owns exactly that kind of composition,
and `PlanIngest` is already the read phase where all I/O belongs (the D7 read/write split: document I/O
stays outside the inbox transaction so the write never pins the cluster xmin and stalls the bus reader).

The ACL keeps admitting a named-but-purl-less finding. That is correct: it IS a real observation. What
changes is that the app no longer lets it become a match without an identity.

## 2. Where the candidate twins come from — and the constraint that forced this

**Constraint found while reading the seam:** `PlanIngest` today builds its bridge sibling set from **the
report's own components**, because a scanner that catalogued both the rpm database and site-packages put
both in one report. But the measured good twin (`pkg:rpm/rocky/httpd@…`) lives in the **SBOM's canonical
inventory**, not in the scanner report. So the existing sibling set cannot answer D2.

**Candidate set = the release's canonical inventory ∪ the report's own usable components.**

- The inventory is the authority on what the release contains, and is where the measured twin lives.
  Reached by release → correlated evidence id (the KN-RECOR-1 ledger) → `GetInventory` — the **same two
  ports `ReverdictService.bridgeFor` already uses**, so this adds a read, not a seam.
- The report's own usable components are included because they are also observations of the same
  release, and the measured document shows twins can travel together.
- **Disagreement between the two sources is ambiguity, and ambiguity abstains** (D2). Two distinct purls
  for one (name, version) is precisely the case where a guess would be wrong, so no tie-break is
  invented.

**Degradation is abstention, never synthesis.** If the ledger has no correlated evidence for the release
(scanner-only) or the inventory read fails, the candidate set is the report alone; if that yields no
unique twin, the observation stays unresolved. This is D8's accepted cost, reached by the same road as
the D6 re-verdict sweep's per-release fail-safety: a poorer context must never be stamped as an answer.

## 3. What "usable purl" means — and the second constraint

**Constraint found while reading the seam:** Knowledge does not validate purls at all today.
`value.NewPURL` (which requires the `pkg:` scheme) is called only in Evidence; `app.InventoryComponent`
carries a bare `string`. So Knowledge currently cannot distinguish `pkg:rpm/rocky/httpd@2.4.57` from
`app:httpd` — and D1 requires exactly that distinction.

**A purl is usable iff `value.NewPURL` accepts it.** The kernel value object is reused, never
re-implemented: a second parser is a second answer, and this is the one place where "is this an identity?"
must have a single definition. Empty and unparseable collapse to the same outcome (unresolved), which is
D1's point — an empty PURL is not an identity, and neither is a string that merely looks like one.

## 4. The unresolved population, and how it is surfaced

`ScannerPlan` gains an `Unresolved []UnresolvedObservation` beside `Items`, carrying the raw identifier,
name, version and ecosystem as observed. It is a **separate population, not a filtered-out one** — the
distinction that makes D6 possible.

Surfacing lands where an operator already looks, and closes **KN-SCAN-OBS-1** at the same time: the
existing `Skipped` counter is computed and never logged, so both populations are invisible today. One log
line per ingest carrying `items` / `skipped` / `unresolved`, plus the count in the read API, on the same
principle the sweeps follow — *logged on every ingest including zero, because "nothing unresolved" and
"the resolver stopped running" must not look alike.*

**Nothing is written for an unresolved observation.** No match row, therefore no empty-purl row, therefore
no primary-key collapse and no Governance rejection — which is how D7's availability property falls out
of the correctness fix rather than needing its own mechanism. Consumer poison resilience stays
PARITY-GAP F7: fixing the producer does not excuse the consumer.

## 5. What is deliberately NOT in this change

- **Historical rows.** Converging existing `app:` rows changes a value that is part of the primary key —
  that is KN-SCAN-4(b), the same work from the opposite end.
- **The carrier-name synonym class.** `http_server` ↔ `httpd` is EDR-3's (EDR-IDENTITY-01 D9). This change
  establishes identity where evidence permits; it does not decide what an unbridgeable mismatch means.
- **A `CanonicalComponent` entity.** Deferred on purpose — a new database entity is a larger commitment
  than the measured evidence justifies.

## Ordering constraint

Phase 1 (the rule) and its surfacing ship **together**, per D6: a correct answer nobody can see is
indistinguishable from a wrong one, and that is the lesson the 2026-09-16 session paid for. Phase 2 (the
SPDX door) is independent and may follow.
