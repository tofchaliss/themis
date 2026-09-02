# Tasks — phase3-occurrence-verdicts

Source of truth: `docs/engineering/decisions/EDR-VERDICT-01.md`. Every group ends with
`make vet-tags` green (tagged files rot silently otherwise) and phase completion gates on `make check`.

## Group 1 — Phase 1: the record book (D1, D2, D5, D7)

- [ ] 1.1 Knowledge domain: occurrence verdict value object (`open` / `cleared_vendor_fix` + grade
      `observed`/`inferred` + reason); missing/unknown reads as `open` everywhere.
- [ ] 1.2 Knowledge migration: `verdict_state` / `verdict_grade` / `verdict_reason` /
      `verdict_card_version` on `faultline_matches` (+ down migration; reversibility gate).
- [ ] 1.3 Unify intake: `judgeOccurrence` seam in the app ring; `ApplyCorrelation` records
      fixed-verdict outcomes as cleared rows instead of `continue`; `ApplyIngest` judges scanner
      occurrences through the same seam (range-rejected candidates still never record).
- [ ] 1.4 `RecordMatch` upsert: state fields update on conflict; rows never deleted; store tests incl.
      pre-feature default rows reading as `open`.
- [ ] 1.5 Events: additive state/grade/reason on `ComponentMatched` (schema declared);
      `knowledge.component_verdict_changed.v1` envelope + schema.
- [ ] 1.6 Governance migration: mirror columns on `finding_components` (+ down); consumer upserts both
      events; unknown state → `open`.
- [ ] 1.7 Governance queue derivation: open-carrier set drives priority (full value, cleared contribute
      zero) and queue membership; projection tests for the measured shape (1 cleared + 1 open carrier →
      queued at full urgency; all-cleared → off queue).
- [ ] 1.8 Read APIs (knowledge + governance): expose state/grade/reason per component (spec-first;
      regenerate).
- [ ] 1.9 `make vet-tags` + `make check` green.

## Group 2 — Phase 2: the ownership bridge (D3, D4, D8-read)

- [ ] 2.1 Evidence read model: surface SBOM ownership relationships in the inventory DTO where the
      document carries them (Syft CycloneDX/SPDX edges); absent → empty, never inferred here.
- [ ] 2.2 Bridge resolver in `judgeOccurrence`: Observed hop (edge → owning rpm → source pkg →
      `RPMFixedByStream` on full EVR) then Inferred hop (same-inventory source-pkg + exact upstream
      version), gated by `THEMIS_VERDICT_INFERRED_BRIDGE` (default on); every missing precondition →
      `open`. Table-driven tests incl. the measured case and the pip-copy-at-distro-version wrong-clear
      bound.
- [ ] 2.3 Reason strings: distinct Observed vs Inferred wording (drawer renders verbatim).
- [ ] 2.4 Per-occurrence fix selection on the read path (ecosystem-matched; unknown → upstream +
      caveat; cleared → none).
- [ ] 2.5 `deploy/node.env.example` + INSTALLATION/TESTING notes for the switch (R2 self-documenting).
- [ ] 2.6 `make vet-tags` + `make check` green.

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
