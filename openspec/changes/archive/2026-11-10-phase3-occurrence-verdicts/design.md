# Design — phase3-occurrence-verdicts

Source of truth for decisions: `docs/engineering/decisions/EDR-VERDICT-01.md` (D1–D9). This file maps
those decisions onto the code; where the two disagree, the EDR wins.

## 1. Occurrence verdict state (Phase 1 — the record book)

**Knowledge, `faultline_matches`** (migration `0000NN`): add

- `verdict_state TEXT NOT NULL DEFAULT 'open'` — `open` | `cleared_vendor_fix`. The enum lives in
  `internal/knowledge/domain` (new value object beside `claimclass.go`); unknown/missing reads as `open`
  everywhere (fail-safe direction, EDR D2/honest limits).
- `verdict_grade TEXT NOT NULL DEFAULT ''` — `''` | `observed` | `inferred` (EDR-TRUST-01 vocabulary,
  set only when cleared).
- `verdict_reason TEXT NOT NULL DEFAULT ''` — the plain-language premise ("vendor fix
  0:39.2.0-9.el8_10 present via platform-python-setuptools"), rendered verbatim by the drawer.
- `verdict_card_version BIGINT NOT NULL DEFAULT 0` — the card version this row was last judged against
  (the D6 stamp). `0` marks pre-feature rows: the catch-up sweep's primary target.

**Unified intake (D2).** `CorrelationService.ApplyCorrelation` and `ScannerReportService.ApplyIngest`
stop dropping/skipping on a fixed-verdict: both call one `judgeOccurrence(card, component)` seam (app
ring) that returns (state, grade, reason), and record the match WITH that state. The reconciled-range
out-of-range drop in correlation remains a drop (it is "this was never a match", not "matched but
fixed") — the EDR's record-everything rule covers examined *matches*, not range-rejected candidates.
`RecordMatch` upsert semantics: on conflict, state fields update (a re-judgement may change state); the
row itself is never deleted.

**Event seam (D5).** `ComponentMatched` gains additive fields (state/grade/reason — schema declared, as
KN-SCAN-2 did for detection_origin). A state CHANGE on an existing row emits
`knowledge.component_verdict_changed.v1` (new envelope, additive; Governance's consumer treats unknown
event types as today — ignored until wired). Governance migration adds the mirror columns to
`finding_components`; the consumer upserts them; queue derivation (below) recomputes on either event.

**Queue derivation (D1/D7).** Governance's read/projection layer computes a Finding's open-carrier set:
carrier occurrences with `verdict_state = open` (missing → open). Priority formulas are unchanged but
range over that set; a Finding with an empty open-carrier set and no open decision obligation leaves the
triage queue (projection-level, no Position is written — "the fix clears rows, never Findings").

## 2. The ownership bridge (Phase 2)

`judgeOccurrence` for a language-ecosystem component with no direct fix match tries the bridge (D3):

1. **Observed:** the inventory component carries an ownership edge (Evidence read model exposes SBOM
   relationships where present — Syft CycloneDX/SPDX emit them; parse is Evidence-side, additive to the
   inventory DTO). Resolve file → binary RPM → source package (existing `componentPackage` source-wins),
   then the unchanged `RPMFixedByStream` on the owning RPM's full EVR.
2. **Inferred:** same inventory holds an rpm component whose source package equals the fix's attributed
   package AND whose upstream version segment equals the language row's version. Same comparator on that
   rpm component's EVR. Gated by `THEMIS_VERDICT_INFERRED_BRIDGE` (default `1`; `0` = strict mode, D4).

Any missing precondition → `open`. The grade and a generated reason string are stored. rpm-first: the
bridge ships for the rpm world only; deb/apk are recorded follow-ups (EDR honest limits), and the seam
takes the ecosystem so they slot in without re-plumbing.

## 3. Re-verdict (Phase 3)

- **Trigger:** `FoldProposal` already reports whether folding changed the card (KN-PROPOSAL-BLOAT-1
  drops verbatim restatements). When a fold changes the reconciled fix set, the enrichment/inbox path
  calls `ReverdictForFaultline(cardID)`: load matches by the existing faultline index, re-judge, stamp
  `verdict_card_version`, emit change events. Read-only inputs; no network.
- **Catch-up sweep:** `VerdictSweep` (pattern: KN-RECOR-1/KN-FIX-2 — bounded batch, interval, idempotent):
  select matches where `verdict_card_version < faultlines.version` (covers `0` = pre-feature rows),
  re-judge, stamp. Config `THEMIS_REVERDICT_INTERVAL` (default 12h), `THEMIS_REVERDICT_BATCH`
  (default 200). A completed sweep selects nothing and writes nothing.
- **Validation binding (EDR):** on the measured estate, the first sweep must clear the
  `setuptools@39.2.0` rows (inferred grade), leave `70.3.0` open, and keep the Finding queued at full
  urgency.

## 4. Remediation + GUI (Phase 4)

- **Fix selection (D8):** the posture/read path already joins the card's fixes; it now selects per
  occurrence by canonical-ecosystem match (rpm occurrence → rpm bound via source package; language
  occurrence → upstream ecosystem fix). Unknown ecosystem → upstream fix + fixed caveat string. Cleared
  occurrences carry no advice.
- **Plan grouping:** `plan_remediation`'s deterministic pre-prompt `GROUP BY` becomes
  (package, canonical world). Prompt contract unchanged otherwise.
- **Drawer (D9):** occurrence list = state pill + grade label + `verdict_reason` + per-occurrence fix;
  cleared rows in a collapsed/quiet section under open ones. Vanilla-JS, same read APIs.

## Ordering constraint

Phases strictly 1 → 2 → 3 → 4 (each writes into the previous phase's structure). Phase 3 is the phase
that heals history; do not declare the arc live-verified before it runs on the estate.
