# Proposal — phase3-gui-react (EDR-GUI-02)

## Why

The dashboard's browser half is one hand-written file (`cmd/dashboard/static/app.js`, 3,160
lines) that builds every screen as HTML strings with hand escaping. Shared parts are copied, not
reused, nothing type-checks the API fields it reads, and nothing tests a screen. The owner asked
on 2026-11-22 to move it to React + shadcn/ui + Tailwind CSS.

## What changes

Built in steps G1-G7 of EDR-GUI-02, one PR each, each on the owner's go:

- **G1** skeleton: `web/dashboard/` (Vite, React, TypeScript, Tailwind, shadcn/ui), Makefile and
  CI gates, CSP and cache headers, the new app at `/next/`, app shell with the three-shade picker
  (Enterprise default, Midnight, Ops night), Overview and Estate.
- **G2** release posture and finding drawer.
- **G3** SBOM manager and scan view.
- **G4** Compare, What's new, CVE page.
- **G5** Reports, Watches, Feeds, Admin.
- **G6** new GUI becomes the default; old GUI at `/classic/` for one release.
- **G7** old GUI and `make js-check` removed.

## Out of scope here

Server rendering, new API endpoints, GUI users and roles (EDR-SCORING-01 S6), SSO, translations,
mobile layout, any node change.

## Impact

New npm toolchain and dependencies (owner approval in EDR-GUI-02), new `web/dashboard/`
directory, committed build output in `cmd/dashboard/static/`, Makefile and CI changes, a CSP
header and cache headers from the dashboard. `go build ./...` and the VM build stay Node-free.
Sign-in, sessions, the proxy and every node API are unchanged.
