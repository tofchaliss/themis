#!/usr/bin/env bash
# Upload an SBOM to a running Themis instance (Phase 1 / 2a walkthrough helper).
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: upload-sbom.sh -f SBOM.json -i IMAGE_ID [options]

Required:
  -f PATH    CycloneDX or SPDX SBOM file
  -i UUID    Registered image ID (see README — insert into images until 16.4 lands)

Optional:
  -u URL     Base URL (default: http://localhost:8080)
  -k KEY     API key (default: $THEMIS_API_KEY)
  -p POLICY  Trust policy: strict|standard|permissive (default: standard)
  -K KEY     Idempotency-Key header value

Example:
  export THEMIS_API_KEY=...
  ./scripts/upload-sbom.sh -f sbom.json -i "$IMAGE_ID"
EOF
}

BASE_URL="${THEMIS_BASE_URL:-http://localhost:8080}"
API_KEY="${THEMIS_API_KEY:-}"
TRUST_POLICY="standard"
IDEMPOTENCY=""
SBOM_FILE=""
IMAGE_ID=""

while getopts "f:i:u:k:p:K:h" opt; do
  case "$opt" in
    f) SBOM_FILE="$OPTARG" ;;
    i) IMAGE_ID="$OPTARG" ;;
    u) BASE_URL="$OPTARG" ;;
    k) API_KEY="$OPTARG" ;;
    p) TRUST_POLICY="$OPTARG" ;;
    K) IDEMPOTENCY="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

if [[ -z "$SBOM_FILE" || -z "$IMAGE_ID" ]]; then
  usage
  exit 1
fi
if [[ -z "$API_KEY" ]]; then
  echo "error: set THEMIS_API_KEY or pass -k" >&2
  exit 1
fi
if [[ ! -f "$SBOM_FILE" ]]; then
  echo "error: SBOM file not found: $SBOM_FILE" >&2
  exit 1
fi

headers=(-H "X-API-Key: ${API_KEY}" -H "Content-Type: application/json")
if [[ -n "$IDEMPOTENCY" ]]; then
  headers+=(-H "Idempotency-Key: ${IDEMPOTENCY}")
fi

curl -sS -X POST "${BASE_URL}/api/v1/images/${IMAGE_ID}/sboms?trust_policy=${TRUST_POLICY}" \
  "${headers[@]}" \
  --data-binary @"${SBOM_FILE}"

echo
