# Tasks — phase3-gui-react

No `specs/` deltas — archive with `openspec archive phase3-gui-react --skip-specs -y`.
Every step waits for the owner's go and lands as its own PR.

## Group 0 — Record

- [ ] 0.1 EDR-GUI-02 merged (status ACCEPTED); EDR-GUI-01 D7/D8 pointer, STACK.md front-end row
  and BACKLOG entry added.

## Group 1 — G1 skeleton

- [ ] 1.1 `web/dashboard/` toolchain: pinned Node, lockfile, Vite, React, TypeScript strict,
  Tailwind, shadcn/ui init, ESLint (no `dangerouslySetInnerHTML`), Vitest, Playwright.
- [ ] 1.2 Makefile `web-install` / `web-build` / `web-check` / `web-verify` / `web-dev`;
  `check` and `check-ci` gain `web-check` and `web-verify`; workflows gain `setup-node`.
- [ ] 1.3 Dashboard: `/next/` mount, cache headers, pre-compressed files, CSP; Go tests.
- [ ] 1.4 Shell: rail, top bar, breadcrumbs, three-shade picker (contrast test), user chip,
  sign-out, default-password notice, session and node-down handling; generated API types.
- [ ] 1.5 Overview and Estate screens at parity, checked against `docs/engineering/gui-reference/`; size budget measured; VM check.

## Group 2 — G2 release posture and drawer

- [ ] 2.1 Release posture (virtual rows, filters, residual priority, SLA, scope chips).
- [ ] 2.2 Finding drawer: decisions, scope picker and preview, AI panels (D6), score panel.
- [ ] 2.3 VM check.

## Group 3 — G3 SBOM manager and scan view

- [ ] 3.1 SBOM manager (upload, new product chain) and scan view at parity; VM check.

## Group 4 — G4 Compare, What's new, CVE page

- [ ] 4.1 The three screens at parity; VM check.

## Group 5 — G5 Reports, Watches, Feeds, Admin

- [ ] 5.1 The four screens at parity (Watches CSV export, admin password change); VM check.

## Group 6 — G6 switch and G7 removal

- [ ] 6.1 `/` serves the new GUI, old GUI at `/classic/`; webhook links checked.
- [ ] 6.2 After one release: old `app.js`, `style.css` and `make js-check` removed.
