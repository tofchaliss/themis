#!/usr/bin/env bash
# Upload an SBOM to a running Themis instance (Phase 1 / 2a walkthrough helper).
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: upload-sbom.sh -f SBOM.json -i IMAGE_ID -d DIGEST [options]

Required:
  -f PATH    CycloneDX or SPDX SBOM file
  -i UUID    Registered artifact ID (from POST /api/v1/products/{id}/artifacts → .id)
  -d DIGEST  Image digest (must match images.digest), e.g. sha256:abc...

Optional:
  -u URL     Base URL (default: http://localhost:8080)
  -k KEY     API key (default: $THEMIS_API_KEY)
  -p POLICY  Trust policy: strict|standard|permissive (default: standard)
  -j UUID    Project ID (optional)
  -K KEY     Idempotency-Key header value

Environment:
  IMAGE_DIGEST  Used when -d is omitted

Example:
  export THEMIS_API_KEY=...
  export IMAGE_DIGEST=$(docker inspect "$IMAGE_REF" --format '{{.Id}}')
  ./scripts/upload-sbom.sh -f sbom.json -i "$IMAGE_ID" -d "$IMAGE_DIGEST"
EOF
}

BASE_URL="${THEMIS_BASE_URL:-http://localhost:8080}"
API_KEY="${THEMIS_API_KEY:-}"
TRUST_POLICY="standard"
IDEMPOTENCY=""
SBOM_FILE=""
IMAGE_ID=""
IMAGE_DIGEST="${IMAGE_DIGEST:-}"
PROJECT_ID="${PROJECT_ID:-}"

while getopts "f:i:d:u:k:p:j:K:h" opt; do
  case "$opt" in
    f) SBOM_FILE="$OPTARG" ;;
    i) IMAGE_ID="$OPTARG" ;;
    d) IMAGE_DIGEST="$OPTARG" ;;
    u) BASE_URL="$OPTARG" ;;
    k) API_KEY="$OPTARG" ;;
    p) TRUST_POLICY="$OPTARG" ;;
    j) PROJECT_ID="$OPTARG" ;;
    K) IDEMPOTENCY="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

if [[ -z "$SBOM_FILE" || -z "$IMAGE_ID" || -z "$IMAGE_DIGEST" ]]; then
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

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required" >&2
  exit 1
fi

format="$(jq -r 'if .bomFormat? == "CycloneDX" then "cyclonedx" elif .spdxVersion? != null then "spdx" else "cyclonedx" end' "$SBOM_FILE")"
spec_version="$(jq -r '.specVersion // .spdxVersion // "1.6"' "$SBOM_FILE")"

headers=(-H "X-API-Key: ${API_KEY}" -H "Content-Type: application/json")
if [[ -n "$IDEMPOTENCY" ]]; then
  headers+=(-H "Idempotency-Key: ${IDEMPOTENCY}")
fi

payload="$(jq -n \
  --slurpfile doc "$SBOM_FILE" \
  --arg format "$format" \
  --arg spec "$spec_version" \
  --arg image_id "$IMAGE_ID" \
  --arg image_digest "$IMAGE_DIGEST" \
  --arg project_id "$PROJECT_ID" \
  '{
    format: $format,
    spec_version: $spec,
    document: $doc[0],
    artifact_id: $image_id,
    image_digest: $image_digest
  } + (if $project_id != "" then {project_id: $project_id} else {} end)')"

curl -sS -X POST "${BASE_URL}/api/v1/sbom/upload?trust_policy=${TRUST_POLICY}" \
  "${headers[@]}" \
  --data "$payload"

echo
