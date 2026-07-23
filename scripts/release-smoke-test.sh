#!/usr/bin/env bash
#
# release-smoke-test.sh — full end-to-end smoke test for a new Themis v0.3.x build.
#
# One deterministic pass:
#   1. build ./bin/themis
#   2. stop any running instance
#   3. DROP + recreate the database (remove old values) and migrate
#   4. run themis (left running in the background)
#   5. provision an admin API key
#   6. register a product + artifact from the sample SBOM (scripts/oamp.json)
#   7. upload the SBOM and poll the ingestion to a terminal state
#   8. verify components are registered
#   9. list the open vulnerabilities (and drop a baseline snapshot)
#
# CVE *enrichment over time* is temporal (background feeds fill severity/EPSS in over
# minutes–hours), so this leaves themis running and captures a baseline; re-run
# scripts/list-open-vulns.sh later to see the day-over-day snapshot diff.
#
# It is long-running (~1–3 min) and DESTRUCTIVE (drops the database) — intended for a clean
# release test. Run it in the background.
#
# Config (env-overridable):
#   THEMIS_DATABASE_DSN, THEMIS_BASE_URL, THEMIS_SBOM, THEMIS_DB_NAME,
#   THEMIS_PG_SUPERUSER, THEMIS_DB_OWNER, THEMIS_API_KEY_FILE
set -euo pipefail

DSN="${THEMIS_DATABASE_DSN:-postgres://themis:themis-dev-password@localhost:5432/themis?sslmode=disable}"
BASE_URL="${THEMIS_BASE_URL:-http://localhost:8080}"
SBOM="${THEMIS_SBOM:-scripts/oamp.json}"
DB="${THEMIS_DB_NAME:-themis}"
SUPERUSER="${THEMIS_PG_SUPERUSER:-$USER}"
OWNER="${THEMIS_DB_OWNER:-themis}"
KEY_FILE="${THEMIS_API_KEY_FILE:-$HOME/.themis_admin_api_key}"
BIN="bin/themis"
API="${BASE_URL%/}/api/v1"

log()  { printf '\n\033[1m=== %s ===\033[0m\n' "$*"; }
die()  { printf '\n\033[31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

# ---- 0. preflight ------------------------------------------------------------------
for c in go psql curl jq; do command -v "$c" >/dev/null || die "missing dependency: $c"; done
[ -f "$SBOM" ] || die "SBOM not found: $SBOM"
export THEMIS_DATABASE_DSN="$DSN"

# ---- 1. stop any running instance --------------------------------------------------
log "1. stop any running themis"
pkill -f 'bin/themis$' 2>/dev/null && sleep 1 || true

# ---- 2. build ----------------------------------------------------------------------
log "2. build ./bin/themis"
go build -o "$BIN" ./cmd/themis || die "build failed"

# ---- 3. fresh database -------------------------------------------------------------
log "3. reset database ($DB) — dropping old values"
psql -h localhost -U "$SUPERUSER" -d postgres -c "DROP DATABASE IF EXISTS $DB WITH (FORCE);" >/dev/null || die "drop db"
psql -h localhost -U "$SUPERUSER" -d postgres -c "CREATE DATABASE $DB OWNER $OWNER;" >/dev/null || die "create db"
make migrate-up >/dev/null 2>&1 || die "migrate failed"

# ---- 4. run themis (detached) ------------------------------------------------------
log "4. start themis"
nohup "$BIN" >themis-smoke.log 2>&1 </dev/null & disown
for _ in $(seq 1 30); do curl -fsS -o /dev/null "$BASE_URL/healthz" 2>/dev/null && break; sleep 1; done
curl -fsS -o /dev/null "$BASE_URL/healthz" 2>/dev/null || die "themis did not become healthy (see themis-smoke.log)"
echo "themis up at $BASE_URL"

# ---- 5. admin API key --------------------------------------------------------------
log "5. provision admin API key"
KEY="$("$BIN" admin create-key --admin --name release-smoke 2>/dev/null | sed -n 's/^api_key=//p')"
[ -n "$KEY" ] || die "could not create api key"
( umask 077; printf '%s' "$KEY" > "$KEY_FILE" )   # so list-open-vulns.sh reuses it
HDR=(-H "X-API-Key: $KEY" -H "Content-Type: application/json")

# ---- 6. register product + artifact ------------------------------------------------
log "6. register product + artifact"
NAME="$(jq -r '.metadata.component.name // "release-under-test"' "$SBOM")"
DIGEST="$(jq -r '.metadata.component.properties[]? | select(.name=="aquasecurity:trivy:RepoDigest") | .value | sub(".*@";"")' "$SBOM" 2>/dev/null | head -1)"
[ -n "$DIGEST" ] || DIGEST="sha256:$(shasum -a 256 "$SBOM" | cut -d' ' -f1)"
PRODUCT_ID="$(curl -fsS -XPOST "$API/products" "${HDR[@]}" --data "$(jq -nc --arg n "$NAME" '{name:$n}')" | jq -r '.id // empty')"
[ -n "$PRODUCT_ID" ] || die "product registration failed"
ARTIFACT_ID="$(curl -fsS -XPOST "$API/products/$PRODUCT_ID/artifacts" "${HDR[@]}" \
  --data "$(jq -nc --arg d "$DIGEST" '{image_digest:$d, version:"under-test"}')" | jq -r '.id // empty')"
[ -n "$ARTIFACT_ID" ] || die "artifact registration failed"
echo "product=$PRODUCT_ID artifact=$ARTIFACT_ID digest=$DIGEST"

# ---- 7. upload SBOM + poll ---------------------------------------------------------
log "7. upload SBOM + poll ingestion"
RESP="$(./scripts/upload-sbom.sh -f "$SBOM" -i "$ARTIFACT_ID" -d "$DIGEST" -k "$KEY")"
ING="$(printf '%s' "$RESP" | jq -r '.ingestion_id // empty')"
[ -n "$ING" ] || die "upload failed: $RESP"
echo "ingestion_id=$ING"
ST=""
for _ in $(seq 1 90); do
  ST="$(curl -fsS "${HDR[@]}" "$API/ingestions/$ING" | jq -r '.status')"
  case "$ST" in
    COMPLETED|NOTIFIED) break ;;
    FAILED|REJECTED)    die "ingestion $ST: $(curl -fsS "${HDR[@]}" "$API/ingestions/$ING" | jq -r '.stage_detail')" ;;
  esac
  sleep 2
done
echo "ingestion status=$ST"

# ---- 8. verify components registered -----------------------------------------------
log "8. verify components registered"
COMPS="$(curl -fsS "${HDR[@]}" "$API/status?top=5" | jq -r '.components.total_registered // 0')"
[ "${COMPS:-0}" -gt 0 ] || die "no components registered"
echo "components registered: $COMPS"

# ---- 9. list open vulnerabilities (+ baseline snapshot) ----------------------------
log "9. list open vulnerabilities"
./scripts/list-open-vulns.sh || true

echo
printf '\033[32m=== SMOKE TEST PASSED ===\033[0m\n'
echo "themis is left running (log: themis-smoke.log)."
echo "Track CVE enrichment over time: re-run scripts/list-open-vulns.sh after a delay —"
echo "its snapshot diff shows unknown→scored severities filling in as the feeds run."
