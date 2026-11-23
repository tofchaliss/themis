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
| `mockup-cve-releases-enterprise.png` | New CVE page, **Affected releases** table, Enterprise. Redrawn from an owner reference screenshot of an older tool (2026-11-23); the original is not committed because it carries real product and ticket names. |
| `mockup-cve-releases-midnight.png` | The same page in Midnight. |
| `mockup.html` | The source of the mockups. `?theme=enterprise|midnight|ops-night`, `&drawer=1` opens the drawer, `&view=cve` shows the CVE page. |
| `render-mockups.js` | Re-renders the PNGs with Playwright: `node docs/engineering/gui-reference/render-mockups.js`. |

What the mockups fix (named so each G-step can check it):

1. **One table everywhere**: same header, filters, sorting and virtual rows on every list (D6).
2. **Summary before detail**: tiles first, then the table; severity always has a text label beside its fixed colour (D7).
3. **The drawer is shorter**: package, version and distro in columns instead of a full purl per line; the full purl is one hover or click away.
4. **The AI is labeled**: "AI · information, proposes no position" on the explanation; "Ask AI" proposes, a person decides (EDR-GUI-01 D6).
5. **The decision bar stays in view** at the bottom of the drawer, with the scope picker (EDR-SYNC-01).
6. **Shade picker** in the top bar with the three shades.
7. **One CVE across releases** (CVE page): one row per affected release with who decided it
   (**AUTO** = a policy rule, **MANUAL** = a named person), the source score next to the Themis
   score, decision date, disposition, rationale, ticket and per-row actions. The two dashed
   boxes mark what the owner's reference highlighted: the "decided by" column and a
   re-evaluate action.

Open points the mockups do not settle (each is decided in the step that builds the screen, and
any new endpoint is a read- or write-API change in the owning context first, EDR-GUI-01 D5):

- **Re-evaluate**: today re-judging is a one-time pass (`THEMIS_GOVERNANCE_REJUDGE_RANGES=1`)
  and the release-evaluation worker; an on-demand re-evaluate for one CVE or one release needs a
  Governance endpoint.
- **Decide for selected**: maps onto EDR-SYNC-01 scope (release / project / product); deciding
  an arbitrary selection of releases is not a scope today.
- **AUTO vs MANUAL** comes from `decided_by` on the Position, which the wire already carries.
