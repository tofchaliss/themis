#!/usr/bin/env bash
# Bootstrap a local Themis + embedded Postgres and run the Alpine E2E gate.
# Requires: go, jq, curl; psql optional (for image + version registration).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PORT="${THEMIS_E2E_PG_PORT:-15450}"
HTTP_PORT="${THEMIS_E2E_HTTP_PORT:-8080}"
BASE_URL="http://127.0.0.1:${HTTP_PORT}"
SBOM="${THEMIS_E2E_SBOM:-${ROOT}/testdata/alpine-busybox.cdx.json}"
WORKDIR="${TMPDIR:-/tmp}/themis-alpine-e2e-$$"
mkdir -p "$WORKDIR"

cleanup() {
  [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null || true
  [[ -n "${PG_PID:-}" ]] && kill "$PG_PID" 2>/dev/null || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "==> Building themis"
make build >/dev/null

echo "==> Starting embedded Postgres on port ${PORT}"
cat > "${WORKDIR}/embeddedpg.go" <<'EOF'
package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
)

func main() {
	port := uint32(15450)
	if len(os.Args) > 1 {
		_, _ = fmt.Sscanf(os.Args[1], "%d", &port)
	}
	dir := os.Args[2]
	cfg := embeddedpostgres.DefaultConfig().
		Username("themis").Password("themis").Database("themis").
		Version(embeddedpostgres.V16).Port(port).
		DataPath(filepath.Join(dir, "data")).
		RuntimePath(filepath.Join(dir, "runtime")).
		BinariesPath(filepath.Join(dir, "bin"))
	db := embeddedpostgres.NewDatabase(cfg)
	if err := db.Start(); err != nil {
		panic(err)
	}
	fmt.Printf("postgres://themis:themis@localhost:%d/themis?sslmode=disable\n", port)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	_ = db.Stop()
}
EOF

/opt/homebrew/bin/go run "${WORKDIR}/embeddedpg.go" "$PORT" "$WORKDIR/pg" >"${WORKDIR}/pg.out" &
PG_PID=$!
for _ in $(seq 1 45); do
  if grep -q '^postgres://' "${WORKDIR}/pg.out" 2>/dev/null; then
    break
  fi
  sleep 1
done
export THEMIS_DATABASE_DSN
THEMIS_DATABASE_DSN=$(grep '^postgres://' "${WORKDIR}/pg.out" | head -1)
if [[ -z "$THEMIS_DATABASE_DSN" ]]; then
  echo "embedded postgres failed to start:" >&2
  cat "${WORKDIR}/pg.out" >&2
  exit 1
fi

echo "==> Migrating"
make migrate-up >/dev/null

CFG="${WORKDIR}/themis.yaml"
cat > "$CFG" <<EOF
server:
  port: ${HTTP_PORT}
database:
  dsn: "${THEMIS_DATABASE_DSN}"
epsskev:
  poll_interval: 30s
exploitdb:
  poll_interval: 30s
vexfeed:
  poll_interval: 30s
nvd:
  poll_interval: 1h
EOF

echo "==> Creating admin API key"
export THEMIS_CONFIG_PATH="$CFG"
export THEMIS_DATABASE_DSN
KEY_OUT=$(./bin/themis admin create-key --admin --name alpine-e2e 2>&1)
export API_KEY
API_KEY=$(echo "$KEY_OUT" | sed -n 's/^api_key=//p')
if [[ -z "$API_KEY" ]]; then
  echo "failed to parse API key:" >&2
  echo "$KEY_OUT" >&2
  exit 1
fi

echo "==> Starting server"
THEMIS_CONFIG_PATH="$CFG" THEMIS_DATABASE_DSN="$THEMIS_DATABASE_DSN" ./bin/themis >"${WORKDIR}/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 60); do
  if curl -fsS "${BASE_URL}/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

echo "==> Waiting for initial EPSS/KEV + vendor VEX sync (120s)"
sleep 120

echo "==> Creating product + project"
export PRODUCT_ID
PRODUCT_ID=$(curl -fsS -X POST "${BASE_URL}/api/v1/products" \
  -H "X-API-Key: ${API_KEY}" -H "Content-Type: application/json" \
  -d '{"name":"alpine-e2e","description":"local gate"}' | jq -r .id)
export PROJECT_ID
PROJECT_ID=$(curl -fsS -X POST "${BASE_URL}/api/v1/products/${PRODUCT_ID}/projects" \
  -H "X-API-Key: ${API_KEY}" -H "Content-Type: application/json" \
  -d '{"name":"main"}' | jq -r .id)

IMAGE_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
ARTIFACT_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
DIGEST="sha256:alpine-e2e-$(date +%s)"

if command -v psql >/dev/null 2>&1; then
  psql "$THEMIS_DATABASE_DSN" -v ON_ERROR_STOP=1 <<SQL
INSERT INTO artifacts (id, artifact_type) VALUES ('${ARTIFACT_ID}', 'image');
INSERT INTO images (id, artifact_id, product_id, project_id, repository, digest)
VALUES ('${IMAGE_ID}', '${ARTIFACT_ID}', '${PRODUCT_ID}', '${PROJECT_ID}', 'alpine/e2e', '${DIGEST}');
INSERT INTO product_versions (product_id, version, release_status)
VALUES ('${PRODUCT_ID}', '1.0.0', 'released')
ON CONFLICT (product_id, version) DO NOTHING;
SQL
else
  echo "warning: psql not found — skipping image registration" >&2
fi

echo "==> Uploading Alpine SBOM"
INGESTION_ID=$(curl -fsS -X POST "${BASE_URL}/api/v1/sbom/upload" \
  -H "X-API-Key: ${API_KEY}" -H "Content-Type: application/json" \
  -H "Idempotency-Key: alpine-e2e-$(date +%s)" \
  -d "$(jq -n \
    --slurpfile doc "$SBOM" \
    --arg image_id "$IMAGE_ID" \
    --arg project_id "$PROJECT_ID" \
    --arg digest "$DIGEST" \
    '{
      format: "cyclonedx",
      spec_version: "1.6",
      document: $doc[0],
      image_id: $image_id,
      project_id: $project_id,
      image_digest: $digest,
      ci_job_id: "alpine-e2e"
    }')" | jq -r .ingestion_id)

for _ in $(seq 1 90); do
  st=$(curl -fsS "${BASE_URL}/api/v1/ingestions/${INGESTION_ID}" -H "X-API-Key: ${API_KEY}" | jq -r .status)
  if [[ "$st" == "NOTIFIED" || "$st" == "COMPLETED" || "$st" == "REJECTED" || "$st" == "FAILED" ]]; then
    echo "ingestion status: $st"
    break
  fi
  sleep 2
done

echo "==> Waiting for post-ingest re-enrich cycle (90s)"
sleep 90

export BASE_URL PRODUCT_ID PROJECT_ID
chmod +x scripts/alpine-e2e-gate.sh
./scripts/alpine-e2e-gate.sh
