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
