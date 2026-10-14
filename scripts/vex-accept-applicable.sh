#!/usr/bin/env bash
# vex-accept-applicable.sh — accept the standing vendor-VEX not_affected proposals whose statement
# Themis has determined DOES cover this release (EDR-VEX-02 D2, VEX-RAISE-1).
#
# WHY THIS EXISTS. A vendor's not_affected statement travels the governed road: Governance raises
# a system proposal on each Finding it covers, and a human decides it — vendor evidence is
# Asserted, so no policy may auto-accept it. On an estate that is one Accept click per Finding;
# after the re-judge pass (THEMIS_GOVERNANCE_REJUDGE_RANGES=1) raised the proposals that never
# had a trigger, it was 174 clicks for compat-libtiff3 alone. This script puts forward the ones
# whose statement is `applicable` and lets ONE person sign them in one run.
#
# WHAT IT DOES NOT DO. It never judges a statement. The judgement is the Governance assessment
# projection's `vendor_statements[].applicability`; a proposal is accepted only when a
# not_affected statement about its package is `applicable` to this release — the same test the
# raise path applies today. Anything else is left standing for the reject script or a human.
# A card whose assessment cannot be read is skipped, never guessed at.
#
# Discovery is read-only SQL; every MUTATION goes through the API, so the event stream stays the
# authoritative mutation path and each acceptance is recorded with its actor and time. Accepting
# establishes a not_affected Position: the disposition watcher (GOV-14b) re-surfaces it if the
# premise drifts, and the Finding can be reopened by a human — but this IS a suppression, which
# is why it is dry-run by default and requires a named person to apply.
#
# WHO DECIDES. The API accepts only a HUMAN decider. --apply requires THEMIS_ACTOR_ID; with
# THEMIS_API_KEY set the node records the authenticated principal (`key:<id>`) instead, and with
# auth disabled it records `dev:<THEMIS_ACTOR_ID>`. A placeholder-looking actor is refused, for
# the measured reason in vex-reject-inapplicable.sh.
#
# Usage:
#   PGBASE="postgres://themis:PASSWORD@localhost:5432" ./scripts/vex-accept-applicable.sh
#   PGBASE=... THEMIS_ACTOR_ID=you@example.com ./scripts/vex-accept-applicable.sh --apply
#
# Dry-run by default. Re-running after --apply is harmless — it only considers `proposed` rows.
set -uo pipefail

GOVERNANCE="${THEMIS_GOVERNANCE_URL:-http://localhost:8083}"
ACTOR="${THEMIS_ACTOR_ID:-}"
APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1

for tool in psql curl jq; do
  command -v "$tool" >/dev/null || { echo "vex-accept: $tool is required" >&2; exit 2; }
done
if [ -z "${PGBASE:-}" ]; then
  echo "vex-accept: set PGBASE, e.g. PGBASE=\"postgres://themis:\$PW@localhost:5432\"" >&2
  exit 2
fi
if [ "$APPLY" = "1" ] && [ -z "$ACTOR" ]; then
  echo "vex-accept: --apply needs THEMIS_ACTOR_ID — an acceptance is recorded against a person" >&2
  exit 2
fi
case "$(printf '%s' "${ACTOR:-}" | tr '[:upper:]' '[:lower:]')" in
  *example.com*|*your.name*|*changeme*|*placeholder*|*'<'*|*'>'*|"api"|"admin"|"test"|"user")
    echo "vex-accept: THEMIS_ACTOR_ID=\"$ACTOR\" looks like a placeholder, not a person." >&2
    exit 2 ;;
esac

api() {
  if [ -n "${THEMIS_API_KEY:-}" ]; then curl -sf -H "X-API-Key: $THEMIS_API_KEY" "$@"; else curl -sf "$@"; fi
}

printf '\n\033[1mTHEMIS — vendor-VEX applicable proposals\033[0m  %s\n' "$(date '+%Y-%m-%d %H:%M')"
if [ "$APPLY" = "1" ]; then
  printf '  mode: \033[31mAPPLY\033[0m — each acceptance establishes a not_affected Position\n\n'
else
  printf '  mode: dry run — nothing is written (pass --apply to act)\n\n'
fi

CANDIDATES="$(psql "$PGBASE/governance?sslmode=disable" -Atc "
SELECT p.finding_id || '|' || p.proposal_id || '|' ||
       coalesce(substring(p.rationale from 'not_affected for ([^ ]*)'), '') || '|' || f.cve
  FROM finding_proposals p
  JOIN findings f ON f.id = p.finding_id
 WHERE p.proposer_id = 'vex-applicability'
   AND p.stance = 'not_affected'
   AND p.status = 'proposed'
 ORDER BY 1;" 2>/dev/null)"

if [ -z "$CANDIDATES" ]; then
  printf '  no standing vendor-VEX proposals — nothing to review\n\n'
  exit 0
fi

TOTAL=0; ACCEPT=0; LEFT=0; SKIP=0; FAIL=0

while IFS='|' read -r finding proposal pkg cve; do
  [ -n "$finding" ] || continue
  TOTAL=$((TOTAL + 1))
  if [ -z "$pkg" ]; then
    printf '  \033[33m?\033[0m %s  no package in the rationale — skipped\n' "$proposal"
    SKIP=$((SKIP + 1)); continue
  fi
  BODY="$(api "$GOVERNANCE/api/v1/findings/$finding/assessment" 2>/dev/null)"
  if [ -z "$BODY" ]; then
    printf '  \033[33m?\033[0m %-24s %s  assessment unreadable — skipped\n' "$pkg" "$cve"
    SKIP=$((SKIP + 1)); continue
  fi
  VERDICTS="$(printf '%s' "$BODY" \
    | jq -r --arg p "$pkg" '[.vendor_statements[]? | select(.package == $p and .status == "not_affected") | .applicability] | join(",")' 2>/dev/null)"
  case ",$VERDICTS," in
    *,applicable,*) ;;
    *)
      printf '  \033[33m=\033[0m %-24s %s  left standing [%s]\n' "$pkg" "$cve" "${VERDICTS:-no statement}"
      LEFT=$((LEFT + 1)); continue ;;
  esac
  printf '  \033[32m+\033[0m %-24s %s  accept — vendor not_affected applies to this release\n' "$pkg" "$cve"
  ACCEPT=$((ACCEPT + 1))
  [ "$APPLY" = "1" ] || continue
  if ! api -X POST -o /dev/null -H 'Content-Type: application/json' \
        --data "$(jq -nc --arg a "$ACTOR" '{actor_id: $a, actor_kind: "human"}')" \
        "$GOVERNANCE/api/v1/findings/$finding/proposals/$proposal/accept" >/dev/null 2>&1; then
    printf '      \033[31m✗\033[0m accept failed for %s\n' "$proposal"
    FAIL=$((FAIL + 1))
  fi
done <<< "$CANDIDATES"

printf '\n  reviewed %d · accept %d · left standing %d · skipped %d\n' "$TOTAL" "$ACCEPT" "$LEFT" "$SKIP"
if [ "$APPLY" = "1" ]; then
  printf '  written: %d accepted, %d failed\n\n' "$((ACCEPT - FAIL))" "$FAIL"
else
  printf '  nothing written — re-run with --apply to act\n\n'
fi
[ "$FAIL" -eq 0 ] || exit 1
