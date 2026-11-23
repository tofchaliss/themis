# Tasks — phase3-gui-react

No `specs/` deltas — archive with `openspec archive phase3-gui-react --skip-specs -y`.
Every step waits for the owner's go and lands as its own PR.

## Group 0 — Record

- [ ] 0.1 EDR-GUI-02 merged (status ACCEPTED); EDR-GUI-01 D7/D8 pointer, STACK.md front-end row
  and BACKLOG entry added.

## Group 1 — G1 skeleton

- [x] 1.1 `web/dashboard/` toolchain: pinned Node, lockfile, Vite, React, TypeScript strict,
  Tailwind, shadcn/ui init, ESLint (no `dangerouslySetInnerHTML`), Vitest, Playwright.
- [x] 1.2 Makefile `web-install` / `web-build` / `web-check` / `web-verify` / `web-dev`;
  `check` and `check-ci` gain `web-check` and `web-verify`; workflows gain `setup-node`.
- [x] 1.3 Dashboard: `/next/` mount, cache headers, pre-compressed files, CSP; Go tests.
- [x] 1.4 Shell: rail, top bar, breadcrumbs, three-shade picker (contrast test), user chip,
  sign-out, default-password notice, session and node-down handling; generated API types.
- [ ] 1.5 Overview and Estate screens at parity, checked against `docs/engineering/gui-reference/`; size budget measured; VM check.

## Group 2 — G2 release posture and drawer

- [ ] 2.1 Release posture (virtual rows, filters, residual priority, SLA, scope chips).
- [x] 2.2 Vulnerabilities list with the releases dropdown (D13) and its read-API changes
  (Governance `GET /faultlines/{faultlineId}/findings`; ticket, publication date and re-evaluate still open).
- [ ] 2.3 Finding drawer read only (AI panels, score panel); decision page with scope picker,
  required rationale, unsaved-changes guard, and the severity warning dialog (D14).
  Done 2026-11-23: read-only drawer (no AI or score panel yet) and the decision page (scope
  picker with preview, required rationale, acceptance terms, waiting proposals, other
  releases, unsaved-changes guard). Open: AI and score panels; the severity warning waits for
  the governed vector change (EDR-SCORING-01 S6).
- [x] 2.5 Owner amendment 2026-11-23 (D13): Original severity and Expert severity in place of
  Score (posture rows gain the two scores from the stored assessment), band beside the CVE,
  and the summary as one small card with two donuts.
- [ ] 2.4 VM check.

## Group 3 — G3 SBOM manager and scan view

- [ ] 3.1 SBOM manager (upload, new product chain) and scan view at parity; VM check.
  Done 2026-11-23: SBOM manager at `#/sbom` (pickers with "New…" registering the
  product → project → release chain, refusing a name that exists; intake door upload with
  the receipt as a pair of counts, the scan date for a CSV, receipt follow for a slow file,
  the refusal reason verbatim with its meaning; VEX through POST /evidence; the release's
  evidence list). Scan view at `#/scan/<id>?rel=&v=` (every claim beside its Finding, claims
  with no Finding shown as filtered, row opens the drawer). The release page gains the Scans
  card and "What the latest SBOM changed". No API change. Open: VM check.

## Group 4 — G4 Compare, What's new, CVE page

- [ ] 4.1 The three screens at parity; VM check.
  Done 2026-11-23: Compare at `#/compare` (Governance's buckets with Original and Expert
  severity, the refusal shown with versions instead of ids, rows open the drawer, the
  compare_releases narration on request); What's new at `#/new` (newest cards ten a page,
  the tag filter, CVE search, NVD's latest published on request with Gather); the CVE card
  at `#/cve/<id>` (summary, severity, signals, ranges, fixes, source ratings, releases by
  name). Shared pieces: the AI reason table and answer view, a plain finding table, a
  pager. No API change. Open: VM check.

## Group 5 — G5 Reports, Watches, Feeds, Admin

- [ ] 5.1 The four screens at parity (Watches CSV export, admin password change); VM check.

## Group 6 — G6 switch and G7 removal

- [x] 6.1 `/` serves the new GUI, old GUI at `/old/` (owner 2026-11-23, done ahead of G2);
  webhook-style `/#/<route>` links forward to `/old/#/<route>` (checked in a browser). VM check pending.
- [ ] 6.2 After one release: old `app.js`, `style.css` and `make js-check` removed.
