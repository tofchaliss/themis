# GUI visual reference (EDR-GUI-02)

Pictures of the dashboard **today** and **mockups of the new React GUI**, so every build step of
EDR-GUI-02 has the same visual reference. The mockups are design targets, not pixel specs: the
data in them is example data, and shadcn/ui components decide the final details.

| File | What it shows |
| --- | --- |
| `today-finding-drawer.png` | The current finding drawer with the CVSS score panel (owner screenshot, 2026-11-23). Every full purl is on screen, which makes the drawer long. |
| `mockup-posture-enterprise.png` | New release posture, **Enterprise** (light, default): summary tiles, filter bar, one data table sorted by residual priority. |
| `mockup-posture-midnight.png` | The same screen in **Midnight** (dark). |
| `mockup-posture-ops-night.png` | The same screen in **Ops night** (darker). |
| `mockup-drawer-enterprise.png` | New finding drawer (a shadcn/ui sheet) over the posture: tabs, the AI explanation labeled as information, the score panel, a compact component table (full purl on hover), and the decision bar with scope. |
| `mockup-drawer-ops-night.png` | The same drawer in **Ops night**. |
| `mockup-vulns-enterprise.png` | New **Vulnerabilities** list (EDR-GUI-02 D13): one row per CVE across the releases in scope; the arrow opens an **Affected releases** dropdown under the CVE. Layout taken from an owner reference screenshot of an older tool (2026-11-23); that screenshot is not committed because it carries real product and ticket names. |
| `mockup-vulns-midnight.png` | The same list in Midnight. |
| `mockup-vulns-ops-night.png` | The same list in Ops night. |
| `mockup-decide-enterprise.png` | New **decision page** (D14): releases and scope, stance, disposition, review-by date, ticket, required rationale, the facts beside the form. The drawer itself only reads. |
| `mockup-decide-severity-warning-enterprise.png` | The **severity change warning** (D14) over the decision page: what changes, a required reason, a confirm checkbox. |
| `mockup-decide-severity-warning-midnight.png` | The same warning in Midnight. |
| `mockup.html` | The source of the mockups. `?theme=enterprise|midnight|ops-night`, `&drawer=1` opens the drawer, `&view=vulns` shows the Vulnerabilities list, `&view=decide` the decision page, `&warn=1` the severity warning. |
| `render-mockups.js` | Re-renders the PNGs with Playwright: `node docs/engineering/gui-reference/render-mockups.js`. |

What the mockups fix (named so each G-step can check it):

1. **One table everywhere**: same header, filters, sorting and virtual rows on every list (D6).
2. **Summary before detail**: tiles first, then the table; severity always has a text label beside its fixed colour (D7).
3. **The drawer is shorter**: package, version and distro in columns instead of a full purl per line; the full purl is one hover or click away.
4. **The AI is labeled**: "AI · information, proposes no position" on the explanation; "Ask AI" proposes, a person decides (EDR-GUI-01 D6).
5. **Decisions on their own page**: the drawer only reads and offers "Decide…"; the full page
   carries scope, stance, disposition, rationale, and a warning before any severity change (D14).
6. **Shade picker** in the top bar with the three shades.
7. **One CVE row, its releases in a dropdown** (Vulnerabilities list, D13): clicking the row
   opens the CVE details drawer; clicking the arrow lists the affected releases with who
   decided each one (AUTO / MANUAL), source and Themis score, dates, disposition,
   rationale and ticket. The column mapping is in EDR-GUI-02 D13.

Open points the mockups do not settle (each is decided in the step that builds the screen, and
any new endpoint is a read- or write-API change in the owning context first, EDR-GUI-01 D5):

- **Re-evaluate**: today re-judging is a one-time pass (`THEMIS_GOVERNANCE_REJUDGE_RANGES=1`)
  and the release-evaluation worker; an on-demand re-evaluate for one CVE or one release needs a
  Governance endpoint.
- **Decide for selected**: maps onto EDR-SYNC-01 scope (release / project / product); deciding
  an arbitrary selection of releases is not a scope today.
- **AUTO vs MANUAL** comes from `decided_by` on the Position, which the wire already carries.
