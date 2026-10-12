/* FROZEN TEST ORACLE — not an operator road, and no longer shipped to any browser.
   See README.md in this directory.

   This is `translateTrivy` as it stood in `cmd/dashboard/static/app.js` (EDR-GUI-01
   D16) until EDR-INTAKE-01 D4 deleted the in-browser translators and made the Go
   converter the one implementation. The two declarations below are that code, moved
   VERBATIM — its output on the fixtures in ../trivy/ is the acceptance oracle
   `trivy_test.go` compares against, so editing it would change the contract rather
   than meet it. The driver at the bottom is the test harness, not part of the oracle.

   Usage (the test's own call):  node translate_trivy.js <trivy-report.json>  */

/* Trivy speaks its own ecosystem vocabulary where the pipeline speaks purl
   types — unmapped values pass through (KN-SCAN-3 is the server-side net). */
const TRIVY_ECOSYSTEMS = {
  "python-pkg": "pypi", "node-pkg": "npm", "gobinary": "golang",
  "gomod": "golang", "jar": "maven", "pom": "maven", "gemspec": "gem",
};

function translateTrivy(j) {
  const findings = [];
  let skipped = 0;
  // GUI-12: observed_at derives from the report's own CreatedAt — the time the tool
  // actually observed — so byte-identical raw re-uploads translate to byte-identical
  // curated documents and Evidence's content addressing dedups them. A fresh timestamp
  // here defeated that (measured live 2026-08-17: the same Trivy file re-uploaded
  // produced a second scan row). Trivy stamps 7-digit fractional seconds; trim to
  // milliseconds for Date.parse. Only a report with no usable CreatedAt falls back to
  // "now" — and the file note says so, because silently losing dedup and visibly
  // losing it must not look alike.
  const created = typeof j.CreatedAt === "string"
    ? Date.parse(j.CreatedAt.replace(/\.(\d{3})\d+(?=Z|[+-])/, ".$1")) : NaN;
  const stamped = !Number.isNaN(created);
  const observed = stamped ? new Date(created).toISOString() : new Date().toISOString();
  for (const r of j.Results || []) {
    for (const v of (r && r.Vulnerabilities) || []) {
      if (!v || !v.VulnerabilityID || !v.PkgName) { skipped++; continue; }
      findings.push({
        cve: v.VulnerabilityID,
        observed_at: observed,
        scanner: "trivy",
        severity: v.Severity || "",
        cvss_score: (v.CVSS && v.CVSS.nvd && v.CVSS.nvd.V3Score) || 0,
        cvss_vector: (v.CVSS && v.CVSS.nvd && v.CVSS.nvd.V3Vector) || "",
        affected: [],
        fixed: v.FixedVersion ? [v.FixedVersion] : [],
        component: {
          purl: (v.PkgIdentifier && v.PkgIdentifier.PURL) || "",
          name: v.PkgName,
          version: v.InstalledVersion || "",
          ecosystem: TRIVY_ECOSYSTEMS[r.Type] || r.Type || "",
          source: "",
        },
      });
    }
  }
  return { findings, skipped, stamped };
}

/* The browser uploaded `JSON.stringify({findings: out.findings})` — that expression,
   not the translator's return value, was the document that got filed, so it is the
   byte sequence under test. */
const j = JSON.parse(require("fs").readFileSync(process.argv[2], "utf8"));
process.stdout.write(JSON.stringify({ findings: translateTrivy(j).findings }));
