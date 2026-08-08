#!/usr/bin/env bash
# Install the Themis Phase-3 greenfield services as systemd units so they survive logout and
# reboot. Generates /etc/themis/<service>.env (from the DB password) + a templated
# /etc/systemd/system/themis@.service, then enables and starts all six.
#
# Prerequisites (see INSTALLATION.md Part A):
#   - PostgreSQL running with the `themis` role and the databases (evidence/knowledge/
#     governance/communication/bus, plus auth and intelligence if you use them) already created.
#     THEMIS_PGPW must be the password that role ACTUALLY has: it is baked into six env files
#     here and nothing reconciles them later, so a mismatch surfaces only at the next restart.
#   - The service binaries built: go build -o bin/ ./cmd/registry ./cmd/evidence \
#       ./cmd/knowledge ./cmd/governance ./cmd/communication ./cmd/intelligence
#   - Any manually-started ./bin/* processes stopped (they'd hold the ports):
#       pkill -f 'bin/(registry|evidence|knowledge|governance|communication|intelligence)'
#
# Run from the repo root, as root, with the DB password in THEMIS_PGPW:
#   sudo THEMIS_PGPW='...' [THEMIS_INTELLIGENCE_MODEL=cyberpal20b:latest] ./deploy/systemd/install-systemd.sh
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 1; }

REPO="$(pwd)"
RUN_USER="${SUDO_USER:-root}"
PGPW="${THEMIS_PGPW:?set THEMIS_PGPW to the themis DB password}"
PGHOST="${THEMIS_PGHOST:-localhost}"
PGPORT="${THEMIS_PGPORT:-5432}"
MODEL="${THEMIS_INTELLIGENCE_MODEL:-cyberpal20b:latest}"
BASE="postgres://themis:${PGPW}@${PGHOST}:${PGPORT}"
BUS="${BASE}/bus?sslmode=disable"

[[ -x "$REPO/bin/registry" ]] || { echo "error: $REPO/bin/registry not found — build the binaries first (see header)"; exit 1; }
[[ -f "$REPO/deploy/systemd/themis@.service.in" ]] || { echo "error: run from the repo root"; exit 1; }

# Registry self-migrates into the shared evidence DB as of 2026-08-07, keeping its own
# `registry_schema_migrations` bookkeeping table so it never reads Evidence's version. Its unit
# gets the PLAIN DSN — the migrations-table parameter is attached internally to a separate
# migration DSN, because pgx forwards an unknown DSN parameter to Postgres and every runtime
# connection would then fail.
#
# This script used to psql the registry schema in by hand instead. That was silently WRONG once a
# second registry migration existed: it loaded 000001 only, so 000002_estate (customers,
# microservices, deployments — the whole estate graph behind blast-radius) was never created on a
# fresh install, and C1/C2 failed on a system that looked correctly installed.

install -d -m 0750 /etc/themis

write_env() { # $1=service ; stdin=service-specific KEY=VALUE lines
  local f="/etc/themis/$1.env"
  {
    echo "THEMIS_LOG_LEVEL=info"
    echo "THEMIS_LOG_FORMAT=json"
    cat
  } > "$f"
  chmod 0640 "$f"; chown "root:$RUN_USER" "$f"
  echo "  wrote $f"
}

# Registry: plain DSN + self-migrate (its own bookkeeping table, see above).
write_env registry <<EOF
THEMIS_DATABASE_DSN=${BASE}/evidence?sslmode=disable
THEMIS_REGISTRY_MIGRATE=1
THEMIS_REGISTRY_ADDR=:8082
EOF

# Evidence: owns the evidence tables and migrates the shared bus event_log.
write_env evidence <<EOF
THEMIS_DATABASE_DSN=${BASE}/evidence?sslmode=disable
THEMIS_BUS_DATABASE_DSN=${BUS}
THEMIS_EVIDENCE_MIGRATE=1
THEMIS_BUS_MIGRATE=1
THEMIS_EVIDENCE_ADDR=:8081
EOF

# Knowledge: :8085 (NOT the buggy :8082 default); reads Evidence inventory + OSV.
write_env knowledge <<EOF
THEMIS_DATABASE_DSN=${BASE}/knowledge?sslmode=disable
THEMIS_BUS_DATABASE_DSN=${BUS}
THEMIS_EVIDENCE_URL=http://localhost:8081
THEMIS_KNOWLEDGE_MIGRATE=1
THEMIS_KNOWLEDGE_ADDR=:8085
EOF

# Governance: AI ON (calls Intelligence at :8086 only on /recommend).
write_env governance <<EOF
THEMIS_DATABASE_DSN=${BASE}/governance?sslmode=disable
THEMIS_BUS_DATABASE_DSN=${BUS}
THEMIS_GOVERNANCE_AI_ENABLED=1
THEMIS_INTELLIGENCE_URL=http://localhost:8086
THEMIS_GOVERNANCE_MIGRATE=1
THEMIS_GOVERNANCE_ADDR=:8083
# THEMIS_INTELLIGENCE_TIMEOUT=300s   # raise WITH THEMIS_LLM_TIMEOUT on the intelligence node
EOF

# Communication: reads Positions back from Governance.
write_env communication <<EOF
THEMIS_DATABASE_DSN=${BASE}/communication?sslmode=disable
THEMIS_BUS_DATABASE_DSN=${BUS}
THEMIS_GOVERNANCE_URL=http://localhost:8083
THEMIS_COMMUNICATION_MIGRATE=1
THEMIS_COMMUNICATION_ADDR=:8084
EOF

# Intelligence: stateless AI gateway over Ollama.
#
# THEMIS_LLM_TIMEOUT here and THEMIS_INTELLIGENCE_TIMEOUT on the Governance node are TWO HALVES OF
# ONE DEADLINE and the shorter one decides. Raising only this side does nothing visible: Governance
# hangs up first, the Gateway sees its request context cancelled mid-provider-call, and logs
# `provider_error` — so a caller-side timeout reads as an Intelligence fault. Both default to 60s;
# for a slower or larger local model raise BOTH.
write_env intelligence <<EOF
THEMIS_GOVERNANCE_URL=http://localhost:8083
THEMIS_OLLAMA_URL=http://localhost:11434
THEMIS_INTELLIGENCE_MODEL=${MODEL}
THEMIS_INTELLIGENCE_ADDR=:8086
# THEMIS_LLM_TIMEOUT=300s
EOF

sed "s#@REPO@#${REPO}#g; s#@USER@#${RUN_USER}#g" \
  "$REPO/deploy/systemd/themis@.service.in" > /etc/systemd/system/themis@.service
echo "  wrote /etc/systemd/system/themis@.service (User=${RUN_USER}, WorkingDirectory=${REPO})"

systemctl daemon-reload
UNITS="themis@registry themis@evidence themis@knowledge themis@governance themis@communication themis@intelligence"
systemctl enable --now $UNITS
echo
echo "started:"
systemctl --no-pager --lines=0 status $UNITS 2>/dev/null | grep -E "themis@|Active:" || true
echo
echo "logs:   journalctl -u themis@knowledge -f"
echo "status: systemctl status 'themis@*'"
