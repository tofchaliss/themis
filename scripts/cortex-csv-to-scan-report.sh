#!/usr/bin/env bash
# Cortex CSV export -> Themis curated scanner-report document.
#
# Produces the {"findings":[...]} envelope internal/knowledge/adapters/evidence/
# scanner_source.go reads, with per-finding fields matching the scannerRecord
# contract in internal/knowledge/adapters/feed/scanner.go.
#
# This is an OPERATOR-SIDE conversion (the TESTING.md jq-recipe road, adapted from
# JSON to CSV). It changes nothing in Themis: what uploads is the curated document,
# exactly as it would be for Trivy.
#
# Usage:  cortex-csv-to-scan-report.sh <cortex.csv> [observed_at RFC3339] > scan-report.json

set -euo pipefail

CSV="${1:?usage: $0 <cortex.csv> [observed_at RFC3339]}"

# observed_at is MANDATORY: feed.parseObserved rejects an empty value and the ACL
# then skips the finding. The Cortex CSV carries no scan timestamp, so it must be
# supplied. Default is the file's own mtime, NOT "now" -- a fixed timestamp keeps a
# re-conversion of the same export byte-identical, so Evidence's content addressing
# dedups it instead of filing a second scan (the GUI-12 lesson in translateTrivy).
if [ -n "${2:-}" ]; then
  OBSERVED="$2"
else
  OBSERVED="$(date -u -r "$CSV" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
           || date -u -d "@$(stat -c %Y "$CSV")" +%Y-%m-%dT%H:%M:%SZ)"
fi

# The CSV is parsed by Python's csv module, not by a regex.
#
# Cortex quotes cve_description/remediation, and those fields CONTAIN NEWLINES: the
# 20.1.0.0-125 export is 1264 physical lines carrying 557 logical rows. A parser that
# splits on "\n" before honouring quotes shreds every such row -- measured 2026-09-10,
# the previous jq implementation aborted with "Cannot use null as object key" at line
# 1264. RFC 4180 multi-line fields are the norm in scanner exports, not an edge case.
exec python3 - "$CSV" "$OBSERVED" <<'PY'
import csv, json, re, sys

path, observed = sys.argv[1], sys.argv[2]

# The ecosystem comes from the purl itself (pkg:rpm/... -> rpm) rather than from
# package_type, which is a single constant and carries no ecosystem information.
# An unmapped value passes through unchanged -- value.NormalizeEcosystem is the
# server-side net (KN-SCAN-3), and an unknown ecosystem filters nothing (KN-FIX-3).
PURL_ECO = re.compile(r"^pkg:([^/]+)/")

# Cortex identifies binaries it fingerprints on disk as package_type APP with an
# application-scoped purl ("app:httpd@2.4.37-65.module+el8.10.0+..."), which carries no
# `pkg:` prefix and therefore no ecosystem. A blank ecosystem closes the verdict path
# outright: StrictFixesFor returns nil without a positive ecosystem, so NO vendor-fix
# verdict can ever fire for that component (KN-SCAN-3b, measured 2026-09-10: 87 httpd
# findings in exactly this state, every one of them un-clearable).
#
# An APP row whose version carries an RPM release marker (".el8", "+el8", ".module+el8")
# IS an rpm package -- the distro built it, the vendor states fixes for it, and the same
# NEVRA comparison applies. Claiming rpm on that evidence is a statement about the
# version's SHAPE, not a guess about the scanner's intent, and anything without the
# marker is left blank exactly as before.
RPM_BUILD = re.compile(r"(\.|\+)el[0-9]")

def num(s):
    try:
        return float(s)
    except (TypeError, ValueError):
        return 0

findings = []
with open(path, newline="", encoding="utf-8") as fh:
    for row in csv.DictReader(fh):
        cve = (row.get("vulnerability_id") or "").strip()
        purl = (row.get("package_purl") or "").strip()
        name = (row.get("origin_package_name") or "").strip()
        # a row with no CVE id or no package identity is unusable -- drop it here
        # rather than uploading a finding the ACL will silently skip
        if not cve or not (purl or name):
            continue

        sev = (row.get("cvss_severity") or "").strip()
        if sev == "Unknown":
            sev = ""

        # fix_versions is comma-or-semicolon separated when present; empty when
        # fix_available is False. These stay UNATTRIBUTED by contract (KN-FIX-1).
        fixed = [v.strip() for v in re.split(r"[;,]", row.get("fix_versions") or "") if v.strip()]

        eco = ""
        m = PURL_ECO.match(purl)
        if m:
            eco = m.group(1)
        version = (row.get("package_version") or "").strip()
        if not eco and RPM_BUILD.search(version):
            eco = "rpm"

        findings.append({
            "cve": cve,
            "observed_at": observed,
            "scanner": "cortex",
            "severity": sev,
            "cvss_score": num((row.get("cvss_score") or "").strip()),
            "cvss_vector": "",
            "affected": [],
            "fixed": fixed,
            "component": {
                "purl": purl,
                "name": name,
                "version": version,
                "ecosystem": eco,
                # `source` is the SOURCE-PACKAGE name, not a path: componentPackage()
                # prefers it over the component name when asking a feed "what fixes THIS
                # package?", because vendors key rpm fixes on the source package
                # (kernel-core -> kernel, perl-Errno -> perl). The Cortex CSV carries no
                # source-RPM column, so the honest value is the package's own name.
                #
                # Measured 2026-09-10: mapping file_path here wrote the literal "Managed
                # by the Package Manager" into component_source for 144+ findings, and
                # every fix lookup for them then asked the feeds about a package of that
                # name and got nothing back, forever.
                "source": name,
            },
        })

json.dump({"findings": findings}, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\n")
PY
