#!/usr/bin/env bash
# range-accept-provable.sh — accept the standing version-range `not_affected` proposals that the
# auto-accept policy left for a human only because of their evidence grade.
#
# WHY THIS EXISTS. The version-range rule raises a system `not_affected` proposal when every
# matched component is provably outside the card's reconciled range, and the shipped policy
# accepts it on its own when the evidence is `observed`. On 2026-10-14 the KN-GO-3 range repair
# raised 313 such proposals on the estate; 74 were `observed` and auto-accepted, 239 were graded
# `asserted` — not because the ranges were weak (they were OSV's and NVD's), but because a Red
# Hat FIX on the same card dragged the range grade down. The grading is fixed (a fix-only
# contributor no longer grades the ranges), but a raised proposal is never re-graded: the log is
# append-only. These proposals are correct, and the decision stays a human's — this script makes
# that human's "yes" a single reviewed command instead of 239 clicks.
#
# WHAT IT ACCEPTS, and nothing else: proposals with proposer `version-range`, stance
# `not_affected`, status `proposed`. Nothing a vendor said, nothing the AI said. The verdict
# behind each one is arithmetic over the card's reconciled range, re-derivable by anyone.
#
# WHO DECIDES. An acceptance establishes an Enterprise Position, and the API accepts only a HUMAN
# decider — so `--apply` requires THEMIS_ACTOR_ID, and every acceptance is recorded against that
# person. With auth enabled the API takes the actor from the authenticated principal and records
# `key:<key-id>`; with auth disabled the declared id is recorded as `dev:<THEMIS_ACTOR_ID>`.
#
# DRY RUN BY DEFAULT. Without --apply it lists what it would accept and writes nothing. Re-running
# after --apply is harmless — it only ever considers proposals still in `proposed`.
#
# Usage:
#   PGBASE="postgres://themis:PASSWORD@localhost:5432" ./scripts/range-accept-provable.sh
#   PGBASE=... THEMIS_ACTOR_ID=you@example.com ./scripts/range-accept-provable.sh --apply
set -uo pipefail

GOVERNANCE="${THEMIS_GOVERNANCE_URL:-http://localhost:8083}"
ACTOR="${THEMIS_ACTOR_ID:-}"
APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1

for tool in psql curl jq; do
  command -v "$tool" >/dev/null || { echo "range-accept: $tool is required" >&2; exit 2; }
done
if [ -z "${PGBASE:-}" ]; then
  echo "range-accept: set PGBASE, e.g. PGBASE=\"postgres://themis:\$PW@localhost:5432\"" >&2
  exit 2
fi
if [ "$APPLY" = "1" ] && [ -z "$ACTOR" ]; then
  echo "range-accept: --apply needs THEMIS_ACTOR_ID — an acceptance is recorded against a person" >&2
  exit 2
fi
case "$(printf '%s' "${ACTOR:-}" | tr '[:upper:]' '[:lower:]')" in
  *example.com*|*your.name*|*changeme*|*placeholder*|*'<'*|*'>'*|"api"|"admin"|"test"|"user")
    echo "range-accept: THEMIS_ACTOR_ID=\"$ACTOR\" looks like a placeholder, not a person." >&2
    echo "  Positions are append-only — the attribution could not be corrected afterwards." >&2
    exit 2 ;;
esac

api() {
  if [ -n "${THEMIS_API_KEY:-}" ]; then curl -sf -H "X-API-Key: $THEMIS_API_KEY" "$@"; else curl -sf "$@"; fi
}

printf '\n\033[1mTHEMIS — provable version-range proposals\033[0m  %s\n' "$(date '+%Y-%m-%d %H:%M')"
if [ "$APPLY" = "1" ]; then
  if [ -n "${THEMIS_API_KEY:-}" ]; then
    printf '  mode: \033[31mAPPLY\033[0m — authenticated; recorded against the API key principal (key:…)\n\n'
  else
    printf '  mode: \033[31mAPPLY\033[0m — auth disabled; recorded as dev:%s\n\n' "$ACTOR"
  fi
else
  printf '  mode: dry run — nothing is written (pass --apply to act)\n\n'
fi

CANDIDATES="$(psql "$PGBASE/governance?sslmode=disable" -Atc "
SELECT p.finding_id || '|' || p.proposal_id || '|' || f.cve || '|' || p.evidence_trust
  FROM finding_proposals p JOIN findings f ON f.id = p.finding_id
 WHERE p.proposer_id = 'version-range'
   AND p.stance = 'not_affected'
   AND p.status = 'proposed'
   AND f.current_stance IS NULL
 ORDER BY f.cve, p.finding_id;" 2>/dev/null)"

if [ -z "$CANDIDATES" ]; then
  printf '  no standing version-range proposals — nothing to accept\n\n'
  exit 0
fi

TOTAL=0; FAIL=0
printf '  %-18s %-10s %s\n' CVE evidence finding
while IFS='|' read -r finding proposal cve trust; do
  [ -n "$finding" ] || continue
  TOTAL=$((TOTAL + 1))
  printf '  %-18s %-10s %s\n' "$cve" "$trust" "$finding"
  [ "$APPLY" = "1" ] || continue
  if ! api -X POST -o /dev/null -H 'Content-Type: application/json' \
        --data "$(jq -nc --arg a "$ACTOR" '{actor_id: $a, actor_kind: "human"}')" \
        "$GOVERNANCE/api/v1/findings/$finding/proposals/$proposal/accept" >/dev/null 2>&1; then
    printf '      \033[31m✗\033[0m accept failed for %s\n' "$proposal"
    FAIL=$((FAIL + 1))
  fi
done <<< "$CANDIDATES"

printf '\n  standing version-range proposals: %d\n' "$TOTAL"
if [ "$APPLY" = "1" ]; then
  printf '  written: %d accepted, %d failed\n' "$((TOTAL - FAIL))" "$FAIL"
  printf '  each acceptance is a Position recorded against you; the Finding leaves the queue\n'
  printf '  and the disposition watcher re-surfaces it if the premise ever moves.\n\n'
else
  printf '  nothing written — re-run with --apply to act\n\n'
fi
[ "$FAIL" -eq 0 ] || exit 1
