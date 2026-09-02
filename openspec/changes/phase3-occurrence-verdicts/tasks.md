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

## Group 3 — Phase 3: re-verdict (D6) — ✅ implemented 2026-09-02

- [x] 3.1 Fold-change trigger — REFINED from the scaffold shape, same semantics: instead of a
      per-fold `ReverdictForFaultline` call threaded through six enrichment services, the
      fix-folding feed loops (redhat · alpine · rocky · nvd backfill · reattribute) call
      `Reverdict.Nudge()` after any tick that folded — the nudged sweep finds EXACTLY the rows
      those folds made stale via the stamps, so "immediate on real card news" holds (seconds,
      not the interval) with no per-CVE bookkeeping and no network anywhere near a fold's
      transaction. vexfeed/signals don't nudge (they never fold fixes); correlation-time folds
      judge inline already. Coalescing, non-blocking.
- [x] 3.2 Catch-up sweep: `ReverdictService.Sweep` over `verdict_card_version < card version`
      (covers pre-feature stamp-0 rows); bridge context rebuilt PER RELEASE — the correlated
      inventory via the KN-RECOR-1 ledger + Evidence read seam, or the release's own recorded
      occurrences for a scanner-only release; an unreadable context SKIPS the whole release
      (stamping a judgement made on poorer context than the evidence offers would silently
      downgrade the verdict). Re-judging goes through the same `RecordMatch` seam (change →
      update + `ComponentVerdictChanged`; confirmation → silent stamp).
      `THEMIS_REVERDICT_INTERVAL` (12h backstop) / `THEMIS_REVERDICT_BATCH` (200); loop in
      `cmd/knowledge` selects ticker + nudge.
- [x] 3.3 Integration test `TestReverdictSweep_FullLoop`: the measured MRF shape on a real
      store — row recorded pre-bounds, redhat fold bumps the card, sweep clears it (inferred,
      reason, stamp current, ONE change event), second sweep reads and writes nothing.
- [x] 3.4 `scripts/vm-verify.sh`: `verdicts: cleared/inferred/stale` line (stale = the sweep's
      remaining queue, should trend to 0); TESTING.md re-verdict watch note; env template.
- [x] 3.5 `make vet-tags` + `make check` green (knowledge app 100% incl. the sweep).

## Group 4 — Phase 4: the face (D8-plan, D9) — ✅ implemented 2026-09-02

- [x] 4.1 Drawer: per-occurrence rows — verdict chip (distinct observed vs inferred wording),
      the clearance's reason verbatim, per-occurrence fix advice matched by canonical world
      (unknown world → advice + explicit "confirm install method" caveat, never a guess);
      cleared rows in a quiet "Cleared — no action needed" section below open ones; the posture
      table's component cell leads with the copy that still matters and shows "✓ all cleared"
      when nothing real is open. `FixedVersion.ecosystem` added to the wire (additive) so the
      client pairs fixes to worlds from server-stated data, not version-shape guessing.
- [x] 4.2 Plan grouping by (package, CANONICAL world) with cleared occurrences contributing
      nothing (`PlanActions` filters `VerdictIsOpen`; readapi decodes `verdict_state`); the
      e2e-llm fixture gains the measured mixed-world finding (cleared distro shadow + open
      python-pkg pip copy → one pypi action, nothing for the shadow).
      **DEPENDENCY CLOSED: KN-SCAN-3** — canonical-world grouping was hollow while
      `CanonicalEcosystem("python-pkg")` passed it verbatim; the kernel alias table gains the
      Trivy analyzer vocabulary and `scanner_source.go` canonicalizes at the parse seam, as
      the backlog item specified.
- [x] 4.3 Docs sweep: BACKLOG (KN-VERDICT-1 implementation note + KN-SCAN-3 ✅), TESTING.md
      verdict how-to (landed in G2/G3); PARITY-GAP untouched (no parity item in this arc).
- [x] 4.4 `make vet-tags` + `make check` green.

## Live validation (binding, EDR "Validation criterion")

- [x] V.1 ✅ **PASSED LIVE 2026-09-02 (~15:55 IST, MRF estate).** All three legs measured:
      (1) `setuptools@39.2.0` cleared on BOTH releases — `cleared_vendor_fix`/`inferred`, reason
      "matched to platform-python-setuptools 39.2.0-9.el8_10 at the distro ve…", Governance
      mirror agreeing; (2) `setuptools@70.3.0` still open (both spellings); (3) the Finding
      still queued at FULL urgency — posture read: `effective_priority: 80, residual_priority:
      80, open_carriers: 1`. Drain: 1080 re-judgements across five 2m sweeps to `stale=0`;
      estate-wide `cleared=17 (inferred=6)` — 11 observed-grade clearances surfaced on rpm
      components whose "checked and fine" was never recorded before. One tooling defect found
      and fixed during the run (release-posture.sh 401'd silently without a key — now shares
      the cached admin key and names the trap).

### V.1 VM procedure (read-only except the deploy itself; VM repo at /opt/themis/src/themis)

1. **Deploy the branch and rebuild.** `git fetch && git checkout feat/occurrence-verdicts &&
   git pull --ff-only`, then `go build -o bin/ ./cmd/...`. Migrations self-apply on restart
   (knowledge `000007`, governance `000012`) via the existing `THEMIS_*_MIGRATE=1` flags in
   `/etc/themis/*.env`.
2. **Speed the history drain for the validation window.** The catch-up sweep is bounded
   (`THEMIS_REVERDICT_BATCH`, default 200/sweep) and its interval defaults to 12h — an estate of
   a few hundred pre-feature rows would take days at defaults. Set
   `THEMIS_REVERDICT_INTERVAL=2m` in the knowledge env for the validation, remove after. NOTE:
   a restarted Red Hat sweep folds ~nothing new (verbatim restatements are dropped —
   KN-PROPOSAL-BLOAT-1), so the NUDGE path will not fire for history; the interval sweep is the
   history healer, by design.
3. **Restart all nodes** (`sudo systemctl restart 'themis@*'`) and watch
   `journalctl -u themis@knowledge -f | grep re-verdict` — expect `rejudged=N changed=M` lines;
   `changed > 0` is the healing event; a persistent `re-verdict sweep failed` means the
   Evidence read is down (rows stay stale, by design).
4. **Verify the binding criterion** (queries in TESTING.md / the chat procedure):
   knowledge `faultline_matches` for CVE-2025-47273 → 39.2.0 rows `cleared_vendor_fix/inferred`
   with reason naming platform-python-setuptools, 70.3.0 rows `open`; governance mirror
   matches; `GET /releases/{id}/posture` → the finding present, `open_carriers=1`,
   effective/residual at FULL value; drawer shows the quiet cleared section with reasons; the
   plan's pypi action names 70.3.0 only. `scripts/vm-verify.sh` → `verdicts:` line with
   `stale` trending to 0.
5. **Tick this box only when all three hold**: cleared-with-reason · still-open pip copy ·
   finding still queued. The finding disappearing entirely FAILS the validation.
