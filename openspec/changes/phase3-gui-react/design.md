# Design — phase3-gui-react

The design of record is `docs/engineering/decisions/EDR-GUI-02.md`. This file only records how
the steps map onto the code.

- **Source** in `web/dashboard/src`: `app/` (shell, router, error boundary), `routes/` (one lazy
  module per screen, hash routes with today's shapes, D4), `components/ui/` (shadcn/ui source),
  `components/` (shared Themis parts: data table, CVE / PURL / version chips, severity badge, AI
  reason panel, node-down panel), `lib/api/` (fetch module + TanStack Query keys, D5),
  `lib/theme/` (three shades, D7), `types/` (generated from `api/*.openapi.yaml`).
- **Build** writes to `cmd/dashboard/static/next/` during G1-G5 and to `cmd/dashboard/static/`
  from G6; the output is committed and `make web-verify` proves it matches the source (D3).
- **Go side** (`cmd/dashboard/main.go`, dashboard binary only): mount `/next/`, cache headers
  and pre-compressed file serving in `assetHandler`, CSP header (D8, D9). No change to the proxy,
  session or gate packages.
- **Parity rule per screen**: every fact, chip, panel and action the old screen shows is listed
  in the step's PR and checked on the VM before the step is ticked. EDR-GUI-01 D6 (AI honesty
  panels, `decided_by`, `precedents_used`, "policy cannot auto-accept this; you can") is part of
  parity, not an extra.
