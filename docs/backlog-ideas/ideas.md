# Backlog — Ideas

Feature ideas, not defects: nothing here is broken, and nothing here carries a priority
against the correctness clusters in [`../BACKLOG.md`](../BACKLOG.md). An idea graduates by
getting a design decision (EDR / "Must ask") and moving into the main backlog as a scoped
item. Tag: **[IDEA]**.

---

## IDEA-1 — [IDEA] Release-comparison read API + fix-verification view (filed 2026-08-14)

**The question it answers:** "CVE-2026-59895 on setuptools — is it fixed in build
`20.1.0.1-110`?" and its general form: *diff two releases' postures — what was fixed, what is
new, what persists.*

**Why it's an idea and not a gap:** the model already answers this, just not in one call.
"Fixed" is deliberately *absence proven by new evidence* — a new build registers as a new
Release, its SBOM correlates, and the CVE's Finding simply does not open there while the old
release keeps its honest record. The cross-release pivot exists today: one Faultline card per
CVE + `GET /faultlines/{id}/releases` (the affected-releases rollup). What's missing is only
the *convenience*: a first-class diff.

**Sketch:** a read-only endpoint (likely Governance or Knowledge, over existing projections —
essentially one join over `faultline_matches` / findings for two release ids) returning
`{fixed:[…], new:[…], persisting:[…]}`, plus a GUI view ("compare releases") on top. Strictly
read-only; stores nothing; no new truth.

**Consumers, known so far:**
1. **Operator fix-verification** — the release-procedure loop measured live 2026-08-14 with
   MRF `v20.1.0.0-118` (the motivating session: SBOM + Trivy scan uploaded, fix-verification
   was answerable only by hand-diffing two posture calls).
2. **G-AI-3's open remainder** (`../BACKLOG.md`) — delta-aware precedent ranking explicitly
   needs "release-comparison machinery that does not exist yet"; this is that machinery.
3. Possibly the AI harness (a `compare_releases` Information capability) once the
   deterministic read exists — deterministic core first, AI as overlay.

**Graduation path:** "Must ask" design-first (new API surface) — already flagged in
`PHASE3-STATUS.md` §2026-08-13 as one of the two big AI blockers. Filing here records the
operator-facing motivation beside the AI-facing one.

**Status 2026-08-14 — consumer 1 (operator fix-verification) REALIZED in the GUI, no
endpoint:** the dashboard's **Compare** tab (`#/compare`, on `feat/gui-multi-scanner-phase-a`)
diffs two releases' postures by CVE entirely client-side — fixed / new / persisting tiles +
tables with drawer deep-links, and an honesty guard that refuses to diff against a release
with no evidence (absence proves nothing until new evidence exists). Two existing posture
reads, a browser join, no new truth — the D1/D15 discipline, so no "Must ask" surface was
touched. Consumers 2–3 (delta-aware precedent ranking, a `compare_releases` capability) still
need the server-side read — the endpoint half of this idea stays open, and the GUI view is
its working spec: what the browser joins by hand is exactly what the endpoint must return.

**Status 2026-08-19 — the endpoint half SHIPPED (EDR-GOVERNANCE-01 D16) and LIVE-VERIFIED the
same day: IDEA-1 is REALIZED.** Witnessed on the VM: MRF v20.1.0.0-109 vs v20.1.0.0-118 diffed
through the Compare tab over the Governance read (104-Finding candidate posture); the honesty
guard earned its keep on the way there — it is what surfaced the silently-swallowed duplicate
upload (EV-DEDUP-1) and the >1 MiB proxy truncation (GUI-14).
Governance now serves `GET /releases/{releaseId}/compare/{candidateId}` → `{fixed, new,
persisting}` in `PostureEntry` rows (fixed carries the baseline's state, new/persisting the
candidate's; sorted by residual then effective priority). The honesty guard moved server-side
and fails CLOSED: 422 names the evidence-less release, 502 when Evidence cannot be asked —
verified over a new `governance/adapters/evidence` read seam (`THEMIS_EVIDENCE_URL`). The
Compare tab now renders this endpoint instead of joining client-side, so the GUI and the AI
consumers read one answer. What remains for consumers 2–3 is only their own work (G-AI-3
ranking; a `compare_releases` capability as an overlay) — the machinery they were blocked on
exists.
