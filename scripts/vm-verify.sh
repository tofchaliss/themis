#!/usr/bin/env bash
# vm-verify.sh — one read-only health-and-state report for a running greenfield deployment.
#
# WHY THIS EXISTS. Verifying a deployment by hand takes five or six round trips: unit states,
# migration versions, pipeline counts, feed health, then whatever the last answer made you
# suspicious about. Each round trip is a hand-written one-liner, and hand-written one-liners are
# where the mistakes live — a `sudo` that cannot expand its own glob, a jq path that silently
# yields null, a query that joins across two databases the architecture keeps apart on purpose.
# This script is that battery, version-controlled, reviewed once, and run as a single command.
#
# It is STRICTLY READ-ONLY. Nothing here mutates state: no restarts, no migrations, no DELETE, no
# credential handling. That is a deliberate boundary — the expensive mistakes on a live estate are
# all mutations, and they should stay in a human's hands where the command is read before it runs.
#
# Usage:
#   PGBASE="postgres://themis:PASSWORD@localhost:5432" ./scripts/vm-verify.sh [RELEASE_ID]
#
# A RELEASE_ID adds a posture sample for that release. Without one the report is estate-wide.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REL="${1:-}"

REGISTRY="${THEMIS_REGISTRY_URL:-http://localhost:8082}"
GOVERNANCE="${THEMIS_GOVERNANCE_URL:-http://localhost:8083}"
KNOWLEDGE="${THEMIS_KNOWLEDGE_URL:-http://localhost:8085}"
INTELLIGENCE="${THEMIS_INTELLIGENCE_URL:-http://localhost:8086}"

for tool in psql curl; do
  command -v "$tool" >/dev/null || { echo "vm-verify: $tool is required" >&2; exit 2; }
done
if [ -z "${PGBASE:-}" ]; then
  echo "vm-verify: set PGBASE, e.g. PGBASE=\"postgres://themis:\$PW@localhost:5432\"" >&2
  exit 2
fi

# Inbound-edge auth is optional (EDR-SECURITY-01): send the key only when one is configured.
get() {
  if [ -n "${THEMIS_API_KEY:-}" ]; then curl -sf -H "X-API-Key: $THEMIS_API_KEY" "$@"; else curl -sf "$@"; fi
}
q() { psql "$PGBASE/$1?sslmode=disable" -Atc "$2" 2>/dev/null; }

ISSUES=0
flag() { ISSUES=$((ISSUES + 1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
info() { printf '    %s\n' "$1"; }

hdr() { printf '\n\033[1m%s\033[0m\n' "$1"; }

printf '\n\033[1mTHEMIS — deployment verification\033[0m  %s\n' "$(date '+%Y-%m-%d %H:%M')"

# ── Services ──────────────────────────────────────────────────────────────────────────────────
hdr "Services"
for svc in registry evidence knowledge governance communication intelligence; do
  state="$(systemctl is-active "themis@$svc" 2>/dev/null || echo unknown)"
  if [ "$state" = "active" ]; then ok "$svc"; else flag "$svc is $state"; fi
done

# ── Migrations ────────────────────────────────────────────────────────────────────────────────
#
# The EXPECTED version is read from the migrations directory rather than hard-coded. A literal
# here would be correct on the day it was written and silently wrong afterwards — which is exactly
# how the systemd installer came to load only the first registry migration and leave a deployment
# without its estate tables. Anything with a generator should be read from the generator.
hdr "Migrations (expected = highest migration on disk)"
check_migration() { # $1=db  $2=table  $3=migrations dir  $4=label
  local want have dirty
  want="$(find "$REPO_ROOT/$3" -name '*.up.sql' 2>/dev/null | sed 's#.*/0*\([0-9]*\)_.*#\1#' | sort -n | tail -1)"
  have="$(q "$1" "select version from $2")"
  dirty="$(q "$1" "select dirty from $2")"
  if [ -z "$have" ]; then flag "$4: no $2 row (did the node ever start?)"; return; fi
  if [ "$dirty" = "t" ]; then flag "$4: version $have but DIRTY — a migration failed part-way"; return; fi
  if [ -n "$want" ] && [ "$have" != "$want" ]; then
    flag "$4: at $have, expected $want — the node is running an older schema than this checkout"
  else
    ok "$4 = $have"
  fi
}
check_migration evidence      registry_schema_migrations internal/registry/adapters/store/migrations      "registry  "
check_migration evidence      schema_migrations          internal/evidence/adapters/store/migrations      "evidence  "
check_migration knowledge     schema_migrations          internal/knowledge/adapters/store/migrations     "knowledge "
check_migration governance    schema_migrations          internal/governance/adapters/store/migrations    "governance"
check_migration communication schema_migrations          internal/communication/adapters/store/migrations "comms     "

# ── Pipeline ──────────────────────────────────────────────────────────────────────────────────
#
# Counted per context and never joined across them: the database-per-context boundary means a
# cross-context join is not merely discouraged, it fails.
hdr "Pipeline"
EV="$(q evidence 'select count(*) from evidence')"
FL="$(q knowledge 'select count(*) from faultlines')"
MA="$(q knowledge 'select count(*) from faultline_matches')"
FN="$(q governance 'select count(*) from findings')"
PO="$(q governance 'select count(*) from finding_positions')"
PU="$(q communication 'select count(*) from publications')"
BUS="$(q bus 'select count(*) from event_log')"
printf '    evidence=%s  faultlines=%s  matches=%s  findings=%s  positions=%s  publications=%s\n' \
  "${EV:-?}" "${FL:-?}" "${MA:-?}" "${FN:-?}" "${PO:-?}" "${PU:-?}"
printf '    bus events=%s\n' "${BUS:-?}"

# A consumer far behind the log is the shape of a stalled reader. It is worth surfacing because the
# stall is silent: the gap-free watermark simply stops admitting rows and nothing errors.
if [ -n "${BUS:-}" ] && [ "${BUS:-0}" -gt 0 ]; then
  while IFS='|' read -r consumer stream seq; do
    [ -z "$consumer" ] && continue
    behind=$((BUS - seq))
    if [ "$behind" -gt 100 ]; then
      flag "reader '$consumer' on '$stream' is $behind events behind (cursor $seq of $BUS)"
    else
      ok "reader $consumer/$stream at $seq"
    fi
  done < <(q bus 'select consumer, source_context, last_seq from stream_cursor order by consumer')
fi

# ── Knowledge: feeds and attribution ───────────────────────────────────────────────────────────
hdr "Feeds"
q knowledge "select source||' '||count(*) from faultline_proposals group by source order by 2 desc" \
  | while read -r line; do info "$line proposals"; done
# A feed with failures is reported; a feed that ran and found nothing is NOT a fault — enrichment
# is relevance-bounded, so a sweep over a cold estate correctly does nothing.
q knowledge "select source||' consecutive_failures='||consecutive_failures from feed_health where consecutive_failures > 0" \
  | while read -r line; do [ -n "$line" ] && flag "$line"; done

hdr "Carrier attribution (EDR-CORRELATION-01)"
CARR="$(q knowledge "select count(*) from faultlines where (view->'carrier_products') is not null and jsonb_array_length(view->'carrier_products') > 0")"
info "cards with carrier products: ${CARR:-0} of ${FL:-0}"
q governance "select coalesce(nullif(claim_class,''),'(unknown)')||' '||count(*) from finding_components group by 1 order by 2 desc" \
  | while read -r line; do info "$line components"; done
info "unknown behaves as carrier — coverage grows as NVD refreshes; it is not a fault"

# ── Intelligence ──────────────────────────────────────────────────────────────────────────────
hdr "AI plane"
if get "$INTELLIGENCE/metrics" >/dev/null 2>&1; then
  reasons="$(get "$INTELLIGENCE/metrics" | grep '^themis_ai_invocations_total' || true)"
  if [ -n "$reasons" ]; then echo "$reasons" | sed 's/^/    /'; else info "no invocations since this process started"; fi
  # The counter is in-process: it resets on restart, so history lives in whatever scrapes it.
  IDX="$(q intelligence 'select count(*) from position_embeddings')"
  if [ -n "$IDX" ]; then info "semantic index: $IDX embedded positions"; else info "semantic precedent disabled (no intelligence DSN)"; fi
else
  flag "intelligence /metrics unreachable"
fi

# ── Release posture (optional) ─────────────────────────────────────────────────────────────────
if [ -n "$REL" ]; then
  hdr "Release posture — $REL"
  if command -v jq >/dev/null; then
    posture="$(get "$GOVERNANCE/api/v1/releases/$REL/posture")" || posture=''
    if [ -n "$posture" ]; then
      info "$(echo "$posture" | jq -r '"findings=\(length)  outstanding=\([.[]|select(.residual_priority>0)]|length)"')"
      info "$(get "$REGISTRY/api/v1/releases/$REL/blast-radius" | jq -r '"customers reached: \(.unique_customers)"')"
      echo "$posture" | jq -r 'sort_by(-.residual_priority, -.base_score) | .[:5][] |
        "    \(.cve)  base=\(.base_score) mult=\(.blast_multiplier) eff=\(.effective_priority) band=\(.band // "-")"'
      # A blast multiplier at its ceiling flattens the queue: every finding above the clamp reads
      # the same effective priority, and the ordering base_score carried is lost (GOV-15).
      pinned="$(echo "$posture" | jq '[.[]|select(.effective_priority==100)]|length')"
      total="$(echo "$posture" | jq 'length')"
      [ "$pinned" -gt $((total / 2)) ] 2>/dev/null && \
        flag "$pinned of $total findings pinned at effective_priority 100 — the multiplier has saturated (GOV-15)"
    else
      flag "posture unreadable for $REL"
    fi
  else
    info "install jq for the posture sample"
  fi
fi

# ── Verdict ───────────────────────────────────────────────────────────────────────────────────
printf '\n'
if [ "$ISSUES" -eq 0 ]; then
  printf '\033[32m✓ no issues found\033[0m\n\n'
else
  printf '\033[31m✗ %d issue(s) above\033[0m\n\n' "$ISSUES"
fi
exit 0
