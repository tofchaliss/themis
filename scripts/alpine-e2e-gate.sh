#!/usr/bin/env bash
# Alpine SBOM bring-up gate (G1–G8) — curl/metrics checks for v0.2.1+.
# Requires a running Themis server, API key, and at least one completed Alpine SBOM ingest.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: alpine-e2e-gate.sh [options]

Checks G1–G8 from project-backlog.md (Alpine E2E bring-up gate).

Environment / flags:
  BASE_URL          Server base URL (default: http://localhost:8080)
  API_KEY           Required — admin or product-scoped key
  PRODUCT_ID        Required for G3/G6 (vex export / coverage)
  SCAN_ID           Required for G4/G5/G8 via scan API (or set PROJECT_ID to resolve latest scan)
  PROJECT_ID        Optional — used to resolve SCAN_ID when unset
  VERSION           Product version for VEX export (default: 1.0.0)
  -h                Show help

Example:
  export API_KEY=...
  export PRODUCT_ID=...
  export PROJECT_ID=...
  ./scripts/alpine-e2e-gate.sh
EOF
}

BASE_URL="${BASE_URL:-http://localhost:8080}"
API_KEY="${API_KEY:-}"
PRODUCT_ID="${PRODUCT_ID:-}"
SCAN_ID="${SCAN_ID:-}"
PROJECT_ID="${PROJECT_ID:-}"
VERSION="${VERSION:-1.0.0}"

while getopts "h" opt; do
  case "$opt" in
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

if [[ -z "$API_KEY" ]]; then
  echo "error: set API_KEY" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required" >&2
  exit 1
fi

AUTH=(-H "X-API-Key: ${API_KEY}")

pass=0
fail=0
skip=0

check() {
  local id="$1" desc="$2" ok="$3"
  if [[ "$ok" == "skip" ]]; then
    echo "SKIP  $id  $desc"
    skip=$((skip + 1))
  elif [[ "$ok" == "true" ]]; then
    echo "PASS  $id  $desc"
    pass=$((pass + 1))
  else
    echo "FAIL  $id  $desc"
    fail=$((fail + 1))
  fi
}

metrics() {
  curl -fsS "${BASE_URL}/metrics"
}

resolve_scan_id() {
  if [[ -n "$SCAN_ID" ]]; then
    return 0
  fi
  if [[ -z "$PROJECT_ID" ]]; then
    return 1
  fi
  SCAN_ID=$(curl -fsS "${BASE_URL}/api/v1/projects/${PROJECT_ID}/scans?limit=1" "${AUTH[@]}" \
    | jq -r '.items[0].id // empty')
}

echo "=== Alpine E2E gate @ ${BASE_URL} ==="

# G1 — EPSS/KEV sync
if metrics | grep 'themis_epsskev_sync_total' | grep -E 'feed="epss"' | grep -q 'status="success"'; then
  epss_ok=true
else
  epss_ok=false
fi
if metrics | grep 'themis_epsskev_sync_total' | grep -E 'feed="kev"' | grep -q 'status="success"'; then
  kev_ok=true
else
  kev_ok=false
fi
if [[ "$epss_ok" == true && "$kev_ok" == true ]]; then
  check G1 "EPSS/KEV sync metrics show success" true
else
  check G1 "EPSS/KEV sync metrics show success" false
fi

# G2 — vendor VEX sync (Alpine zip source)
if metrics | grep -E 'themis_vexfeed_sync_total\{[^}]*feed="alpine"[^}]*status="success"' | grep -q .; then
  check G2 "Alpine vendor VEX sync success" true
else
  check G2 "Alpine vendor VEX sync success" false
fi

# G3 — VEX export without manual SQL (still blocked on product-version registration)
if [[ -z "$PRODUCT_ID" ]]; then
  check G3 "VEX export reachable (needs PRODUCT_ID)" skip
else
  code=$(curl -s -o /tmp/themis-vex.json -w "%{http_code}" \
    "${BASE_URL}/api/v1/products/${PRODUCT_ID}/versions/${VERSION}/vex?format=cyclonedx" "${AUTH[@]}")
  total=$(jq -r '.metadata.component // .vulnerabilities | if type == "array" then length else 0 end' /tmp/themis-vex.json 2>/dev/null || echo 0)
  if [[ "$code" == "200" ]] && [[ "${total:-0}" -gt 0 ]]; then
    check G3 "VEX export returns findings" true
  else
    check G3 "VEX export returns findings (HTTP ${code})" false
  fi
fi

resolve_scan_id || true

if [[ -z "$SCAN_ID" ]]; then
  check G4 "Scan API shows epss_score" skip
  check G5 "Scan API shows risk_score > 0" skip
  check G8 "Scan API shows non-informational deterministic_level" skip
else
  vulns=$(curl -fsS "${BASE_URL}/api/v1/scans/${SCAN_ID}/vulnerabilities?limit=200" "${AUTH[@]}")
  epss_count=$(echo "$vulns" | jq '[.items[]? | select(.enrichment.epss_score != null)] | length')
  risk_count=$(echo "$vulns" | jq '[.items[]? | select(.enrichment.risk_score != null and .enrichment.risk_score > 0)] | length')
  level_count=$(echo "$vulns" | jq '[.items[]? | select(.enrichment.deterministic_level != null and .enrichment.deterministic_level != "informational")] | length')
  if [[ "${epss_count:-0}" -gt 0 ]]; then
    check G4 "Scan API enrichment.epss_score present" true
  else
    check G4 "Scan API enrichment.epss_score present" false
  fi
  if [[ "${risk_count:-0}" -gt 0 ]]; then
    check G5 "Scan API enrichment.risk_score > 0" true
  else
    check G5 "Scan API enrichment.risk_score > 0" false
  fi
  if [[ "${level_count:-0}" -gt 0 ]]; then
    check G8 "Layer 1 deterministic_level non-informational" true
  else
    check G8 "Layer 1 deterministic_level non-informational" false
  fi
fi

# G6 — vendor VEX coverage
if [[ -z "$PRODUCT_ID" ]]; then
  check G6 "vex-coverage covered > 0" skip
else
  cov=$(curl -fsS "${BASE_URL}/api/v1/products/${PRODUCT_ID}/versions/${VERSION}/vex-coverage" "${AUTH[@]}")
  covered=$(echo "$cov" | jq -r '.covered // 0')
  if [[ "${covered:-0}" -gt 0 ]]; then
    check G6 "vex-coverage covered > 0" true
  else
    check G6 "vex-coverage covered > 0 (covered=${covered})" false
  fi
fi

# G7 — status CVSS
status=$(curl -fsS "${BASE_URL}/api/v1/status?top=5" "${AUTH[@]}")
max_cvss=$(echo "$status" | jq '[.top_components[]?.highest_cvss_score // 0] | max // 0')
if awk -v v="$max_cvss" 'BEGIN { exit !(v > 0) }'; then
  check G7 "status top_components highest_cvss_score > 0" true
else
  check G7 "status top_components highest_cvss_score > 0" false
fi

echo "---"
echo "Summary: pass=${pass} fail=${fail} skip=${skip}"
if [[ "$fail" -gt 0 ]]; then
  exit 1
fi
