# Tasks — phase3-component-identity

Source of truth: `docs/engineering/decisions/EDR-IDENTITY-01.md`. Every group ends with `make vet-tags`
green (a tagged file rots silently otherwise — that is why the target exists, and it caught two stale
callers on 2026-09-17), and phase completion gates on `make check-ci`.

Groups 1 and 2 ship TOGETHER (D6). Group 3 is independent.

## Group 1 — Phase 1: the rule (D1, D2, D3, D4)

- [ ] 1.1 Kernel/Knowledge boundary: a `UsablePURL(string) bool` helper in the Knowledge app ring that
      delegates to `value.NewPURL` — reused, never re-implemented. Knowledge does not validate purls
      today (`NewPURL` is Evidence-only), and D1 requires it to tell an identity from a string.
      Empty and unparseable must collapse to one outcome.
- [ ] 1.2 `app.UnresolvedObservation` (raw identifier as observed, name, version, ecosystem, origin) and
      `ScannerPlan.Unresolved` beside `Items` — a separate POPULATION, not a filtered-out one. That
      distinction is what makes D6 possible at all.
- [ ] 1.3 The resolver (`internal/knowledge/app/identity.go`): given an observation and a candidate set,
      return the canonical PURL when **exactly one** candidate matches by name+version; otherwise
      abstain. Never synthesize (D3), never skip (D4). Pure function, no I/O — app tier 100%.
- [ ] 1.4 Candidate set in `PlanIngest`: the release's canonical inventory ∪ the report's own usable
      components, deduped by purl. Reached via the **existing** `ReleaseEvidenceSource` +
      `InventoryReader` ports (the same two `ReverdictService.bridgeFor` uses) — wire them onto
      `ScannerReportService`, do not add a seam.
- [ ] 1.5 Degradation is abstention: no correlated evidence for the release (scanner-only) or a failed
      inventory read ⇒ candidate set is the report alone; still no unique twin ⇒ unresolved. A poorer
      context must never be stamped as an answer (the same rule as the D6 sweep's per-release skip).
- [ ] 1.6 `ApplyIngest` records matches ONLY for resolved items. No row is written for an unresolved
      observation, so no `component_purl = ''` row can exist — which is how D7's availability property
      falls out of the correctness fix instead of needing its own mechanism.
- [ ] 1.7 Tests, each pinned to the measured case: the exact twin resolves
      (`app:httpd` + name/version ⇒ `pkg:rpm/rocky/httpd@…`); two distinct purls for one (name, version)
      abstain; zero candidates abstain; a synthesized `pkg:generic/` appears nowhere; an unparseable
      purl and an empty purl take the same path; a resolved observation collapses onto the twin's
      existing row under the current PK (no duplicate occurrence).
- [ ] 1.8 `make vet-tags` green.

## Group 2 — Phase 1: surfacing (D6) — ships WITH Group 1

- [ ] 2.1 One log line per ingest carrying `items` / `skipped` / `unresolved`, emitted on EVERY ingest
      including zero — "nothing unresolved" and "the resolver stopped running" must not look alike
      (the NVD-WATCH-1 rule, applied to a third sweep).
- [ ] 2.2 Closes **KN-SCAN-OBS-1** in the same change: the existing `Skipped` counter is computed and
      never logged, so both populations are invisible today. Mark it done in BACKLOG.md when this lands.
- [ ] 2.3 The unresolved count reaches an operator without reading logs — Knowledge read API, and
      `scripts/vm-verify.sh` (which already reports the pipeline counts, and whose generations are read
      from source rather than hard-coded; follow that pattern for anything version-like).
- [ ] 2.4 An unresolved observation is **countable and discoverable, and is NOT a bystander.** Assert it
      explicitly: conflating unresolved with `scope` would make this change cause the exact defect
      EDR-CORRELATION-01 exists to prevent.
- [ ] 2.5 `make vet-tags` green; `make check-ci` green — Groups 1+2 gate together as one deployable unit.

## Group 3 — Phase 2: the SPDX door (D4)

- [ ] 3.1 Bring the SPDX parser's purl-less handling under the same rule, so the asymmetry closes from
      both sides rather than one door adopting the other's behaviour. The parser has TWO identity signals
      it discards today — `primaryPackagePurpose` and `supplier` — and the measured document carries **no
      CPE**, so any design resting on CPE is unverifiable on this estate and must not be taken.
- [ ] 3.2 Evidence tier coverage held (parser is 100% today).
- [ ] 3.3 `make vet-tags` green; `make check-ci` green.

## Validation criterion (binding — from EDR-IDENTITY-01)

On the measured MRF document, after Groups 1+2:

- [ ] V1 The purl-less httpd twin resolves onto `pkg:rpm/rocky/httpd@…` — **one** component, not two
      security subjects.
- [ ] V2 No component is recorded with `component_purl = ''` on any path.
- [ ] V3 An ambiguous or twin-less purl-less observation is retained, counted as unresolved, and visible.
- [ ] V4 `pkg:generic/` appears nowhere.
- [ ] V5 After Group 3, the SPDX and scanner doors agree on the same input.

## Out of scope (stated so it is not re-litigated)

- Historical `app:` rows — **KN-SCAN-4(b)**, the same work from the opposite end (changing a value that
  is part of the primary key).
- The carrier-name synonym class (`http_server` ↔ `httpd`) — **EDR-3** (EDR-IDENTITY-01 D9). Priced at
  174 `httpd` component rows classified `scope`, 148 of them also `cleared_vendor_fix`.
- Consumer poison-message resilience — **PARITY-GAP F7**. Fixing the producer does not excuse the
  consumer; they are two independent defects.
- A `CanonicalComponent` database entity — deferred deliberately.
