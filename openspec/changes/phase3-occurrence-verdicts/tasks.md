# Tasks — phase3-occurrence-verdicts

Source of truth: `docs/engineering/decisions/EDR-VERDICT-01.md`. Every group ends with
`make vet-tags` green (tagged files rot silently otherwise) and phase completion gates on `make check`.

## Group 1 — Phase 1: the record book (D1, D2, D5, D7) — ✅ implemented 2026-09-02

- [x] 1.1 Knowledge domain: occurrence verdict value object (`open` / `cleared_vendor_fix` + grade
      `observed`/`inferred` + reason); missing/unknown reads as `open` everywhere.
      (`internal/knowledge/domain/verdict.go`)
- [x] 1.2 Knowledge migration `000007_match_verdict`: `verdict_state` / `verdict_grade` /
      `verdict_reason` / `verdict_card_version` on `faultline_matches` (+ down). Pre-feature rows
      default `'open'`@stamp 0 — the catch-up sweep's target.
- [x] 1.3 Unify intake: `judgeOccurrence` seam (`app/verdict.go`) shared by `ApplyCorrelation`
      and `ApplyIngest`; fixed-verdict outcomes recorded as cleared rows instead of `continue`;
      range-rejected candidates still never record (they were never matches).
- [x] 1.4 `RecordMatch`: select-then-record; a semantic state CHANGE updates the row + emits
      `ComponentVerdictChanged`; a confirming re-judgement refreshes the stamp silently; rows
      never deleted. Integration test `TestRecordMatch_VerdictLifecycle`.
- [x] 1.5 Events: additive VerdictState/Grade/Reason on `ComponentMatched` (schema updated);
      `knowledge.component_verdict_changed.v1` event + schema + contract-test cases.
- [x] 1.6 Governance migration `000012_component_verdict`: mirror columns on `finding_components`
      (+ down); consumer dispatches both events; empty replayed state never blanks a recorded one
      (upsert CASE guard); unknown state reads `open`. `Store.SetComponentVerdict` mirrors
      re-judgements in place (miss = no-op). Integration test `TestComponentVerdictMirror`.
- [x] 1.7 Governance queue derivation (D7): `OpenCarriers` per posture entry; one live carrier →
      FULL priority; components present + zero open carriers → effective/residual 0 (off the
      ranked queue); no component rows → untouched (missing evidence never clears).
      `TestReleasePosture_QueueDerivesFromOpenCarriers` encodes the measured MRF shape.
- [x] 1.8 Read API: governance Component gains `verdict_state`/`verdict_grade`/`verdict_reason`,
      PostureEntry gains `open_carriers` (spec-first, regenerated). CORRECTION to the scaffold:
      Knowledge's read API exposes no matches/components surface, so there is nothing to extend
      there — the occurrence surface is Governance's, where the components already live.
- [x] 1.9 `make vet-tags` + `make check` green (domain/app rings at 100% both contexts).

## Group 2 — Phase 2: the ownership bridge (D3, D4, D8-read) — ✅ implemented 2026-09-02

- [x] 2.1 Evidence: SPDX parser recognizes Syft's `OTHER` + `ownership-by-file-overlap` comment as
      a first-class edge (direction owner→owned preserved); already flows through the existing
      `dependencies` read-API field, no spec change. Knowledge's client maps ONLY ownership edges
      into `Inventory.Owners` (owned→owner); depends_on is not ownership. CORRECTION to the
      scaffold: CycloneDX carries no ownership representation — SPDX-only, matching the EDR's
      honest limit (Trivy-only estates run on the Inferred grade).
- [x] 2.2 Bridge in `judgeOccurrence` via `BridgeContext` (siblings + owners + switch), carried on
      both plans (correlation: the release inventory; scanner: the report's own component set —
      Trivy catalogues the rpm DB beside site-packages, so the report IS a same-inventory set).
      Observed hop: edge → rpm-class owner in the sibling set → owner's own stream verdict.
      Inferred hop: rpm sibling whose fix-attribution key normalizes to the language row's name
      (equality, one distro-wrapper strip — the guard that keeps version equality from clearing
      strangers) + exact upstream-version match + sibling at/above the bound. Gated by
      `THEMIS_VERDICT_INFERRED_BRIDGE` (default on; wiring `VerdictConfig.DisableInferredBridge`
      so the zero value keeps the default). Tests: the measured MRF case, the pip-copy-below-fix
      bound (must stay open), the pinned exact-distro-version wrong-clear limit, name-affinity
      guard, strict mode at service level through both doors.
- [x] 2.3 Reason strings distinct per grade ("owned by X (SBOM ownership): …" vs "matched to X at
      the distro version (inferred, no ownership edge): …"), each naming the bound.
- [x] 2.4 Fix selection: `selectFixesFor` skips CLEARED occurrences — a cleared row pulls no fix
      into the Finding's list; all-cleared ⇒ empty list + unattributed count. (Ecosystem-matched
      selection already existed via KN-FIX-3 `fixAppliesTo`; the unknown-world caveat string is
      drawer presentation → Group 4.)
- [x] 2.5 `deploy/node.env.example` documents the switch + grades; TESTING.md gains the verdict
      how-to. (INSTALLATION defers to the env template, per R2.)
- [x] 2.6 `make vet-tags` + `make check` green (knowledge app back at 100% incl. bridge branches).

## Group 3 — Phase 3: re-verdict (D6)

- [ ] 3.1 Fold-change trigger: on a fix-set-changing fold, `ReverdictForFaultline` re-judges that
      card's matches, stamps `verdict_card_version`, emits change events (no network in the write tx —
      D7 read/write split).
- [ ] 3.2 Catch-up sweep: bounded batch over `verdict_card_version < card version` (incl. `0`
      pre-feature rows); `THEMIS_REVERDICT_INTERVAL` / `THEMIS_REVERDICT_BATCH`; idempotent (completed
      sweep writes nothing); wiring in `cmd/knowledge`.
- [ ] 3.3 Integration test: matches recorded BEFORE bounds fold get cleared by the sweep; stamps
      advance; re-run writes nothing.
- [ ] 3.4 `scripts/vm-verify.sh`: verdict-state counts + sweep lag in the read-only report.
- [ ] 3.5 `make vet-tags` + `make check` green.

## Group 4 — Phase 4: the face (D8-plan, D9)

- [ ] 4.1 Drawer: per-occurrence rows (state pill, grade label, reason, per-occurrence fix); cleared
      rows in a quiet section below open ones.
- [ ] 4.2 `plan_remediation` pre-prompt grouping → (package, canonical world); e2e-llm fixture keeps a
      mixed-world release.
- [ ] 4.3 Docs sweep in the same change: BACKLOG (KN-VERDICT-1 phase ticks), PARITY-GAP if touched,
      TESTING.md drawer/verdict how-to.
- [ ] 4.4 `make vet-tags` + `make check` green.

## Live validation (binding, EDR "Validation criterion")

- [ ] V.1 On the estate: CVE-2025-47273 → `setuptools@39.2.0` occurrences cleared (grade `inferred`,
      reason naming `platform-python-setuptools-39.2.0-9.el8_10`), `setuptools@70.3.0` still open with
      upstream advice, Finding still queued at full urgency. The finding must NOT disappear.
