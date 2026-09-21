#!/usr/bin/env bash
# vex-reject-inapplicable.sh — reject the standing vendor-VEX proposals that rest on a statement
# Themis has determined does not cover this release (EDR-VEX-02 D2/D7, DEF_VEX_COVERING_FIRST_MATCH).
#
# WHY THIS EXISTS. The system proposals raised before EDR-VEX-02 were raised with NO scope check:
# `coveringStatement` took the first statement whose package matched, and which statement that was
# came down to array order in Red Hat's JSON. Measured on the estate 2026-09-21: 132 of 140
# standing proposals rest on a statement about a product the estate does not run — RHEL 9, 6, 5,
# 10, Hardened Images, Ansible, JBoss — each sitting in a reviewer's queue with an Accept button.
# The fix blocks NEW ones; it cannot withdraw old ones, because a proposal id is keyed on
# (finding, package) with no scope in it, so a re-raise is a duplicate and a no-op.
#
# WHAT IT DOES NOT DO. It never decides a Finding. Rejecting a `not_affected` proposal establishes
# no Position and suppresses nothing — the Finding stays open and in the queue. That is the only
# safe direction here: the failure mode of rejecting too much is extra review work, the failure
# mode of accepting too much is a hidden vulnerability.
#
# WHERE THE JUDGEMENT COMES FROM. Not from this script. It asks the Governance assessment
# projection, whose `vendor_statements[].applicability` is the domain's own determination
# (`applicable` / `not_applicable` / `unknown`). A proposal is rejected only when NO statement
# covering its package is `applicable`. A card whose assessment cannot be read is skipped rather
# than guessed at.
#
# `unknown` counts toward rejection, and the report keeps it SEPARATE from `not_applicable`,
# because D4 insists the two are different statements: "this does not apply" versus "I cannot
# determine whether this applies". Both reach the same action here, for one reason — the FIXED
# raise path blocks on anything that is not `applicable`, so a proposal resting on an all-`unknown`
# package is one today's code would never have raised. And the direction is safe either way:
# rejecting keeps the Finding OPEN, so acting on uncertainty costs review work, never coverage.
# An all-`unknown` group usually means the release itself could not be placed — a Finding whose
# components are pypi or npm rather than rpm has nothing that says which distro major it is — and
# the report shows that count so it can be read as its own finding rather than as 132 mismatches.
#
# Discovery is read-only SQL; every MUTATION goes through the API, so the event stream stays the
# authoritative mutation path and each rejection is recorded with its actor and time.
#
# WHO DECIDES. A rejection is a governed decision, and the API accepts only a HUMAN decider —
# `actor_id` is required and a system actor is refused. That boundary is deliberate and this
# script does not work around it: --apply requires THEMIS_ACTOR_ID, and every rejection is
# recorded against that person. The script decides WHICH proposals to put forward; a human signs
# them.
#
# Usage:
#   PGBASE="postgres://themis:PASSWORD@localhost:5432" ./scripts/vex-reject-inapplicable.sh
#   PGBASE=... THEMIS_ACTOR_ID=you@example.com ./scripts/vex-reject-inapplicable.sh --apply
#
# Dry-run by default: it prints the decision for every candidate and changes nothing. Re-running
# after --apply is harmless — it only ever considers proposals still in `proposed`.
set -uo pipefail

GOVERNANCE="${THEMIS_GOVERNANCE_URL:-http://localhost:8083}"
ACTOR="${THEMIS_ACTOR_ID:-}"
APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1

for tool in psql curl jq; do
  command -v "$tool" >/dev/null || { echo "vex-reject: $tool is required" >&2; exit 2; }
done
if [ -z "${PGBASE:-}" ]; then
  echo "vex-reject: set PGBASE, e.g. PGBASE=\"postgres://themis:\$PW@localhost:5432\"" >&2
  exit 2
fi
if [ "$APPLY" = "1" ] && [ -z "$ACTOR" ]; then
  echo "vex-reject: --apply needs THEMIS_ACTOR_ID — a rejection is recorded against a person" >&2
  exit 2
fi

# Inbound-edge auth is optional (EDR-SECURITY-01): send the key only when one is configured.
api() {
  if [ -n "${THEMIS_API_KEY:-}" ]; then curl -sf -H "X-API-Key: $THEMIS_API_KEY" "$@"; else curl -sf "$@"; fi
}

printf '\n\033[1mTHEMIS — vendor-VEX proposal review\033[0m  %s\n' "$(date '+%Y-%m-%d %H:%M')"
if [ "$APPLY" = "1" ]; then
  printf '  mode: \033[31mAPPLY\033[0m — rejections will be written, recorded against %s\n\n' "$ACTOR"
else
  printf '  mode: dry run — nothing is written (pass --apply to act)\n\n'
fi

# The package is read out of the rationale because that is where the raise recorded WHICH
# statement it used; `vexRationale` writes the vendor's package and justification verbatim.
CANDIDATES="$(psql "$PGBASE/governance?sslmode=disable" -Atc "
SELECT p.finding_id || '|' || p.proposal_id || '|' ||
       coalesce(substring(p.rationale from 'not_affected for ([^ ]*)'), '') || '|' ||
       coalesce(substring(p.rationale from 'not affected in ([^)]*)'), '(no product stated)')
  FROM finding_proposals p
 WHERE p.proposer_id = 'vex-applicability'
   AND p.stance = 'not_affected'
   AND p.status = 'proposed'
 ORDER BY 1;" 2>/dev/null)"

if [ -z "$CANDIDATES" ]; then
  printf '  no standing vendor-VEX proposals — nothing to review\n\n'
  exit 0
fi

TOTAL=0; REJECT=0; KEEP=0; SKIP=0; FAIL=0; MISMATCH=0; UNPLACEABLE=0

while IFS='|' read -r finding proposal pkg product; do
  [ -n "$finding" ] || continue
  TOTAL=$((TOTAL + 1))

  if [ -z "$pkg" ]; then
    printf '  \033[33m?\033[0m %s  no package in the rationale — skipped\n' "$proposal"
    SKIP=$((SKIP + 1)); continue
  fi

  BODY="$(api "$GOVERNANCE/api/v1/findings/$finding/assessment" 2>/dev/null)"
  if [ -z "$BODY" ]; then
    printf '  \033[33m?\033[0m %s  assessment unreadable — skipped (never guessed)\n' "$pkg"
    SKIP=$((SKIP + 1)); continue
  fi

  # Themis's own determination, for the statements about THIS package. Absent vendor_statements
  # (a Knowledge the projection could not reach) yields an empty answer, which is a skip.
  VERDICTS="$(printf '%s' "$BODY" \
    | jq -r --arg p "$pkg" '[.vendor_statements[]? | select(.package == $p) | .applicability] | join(",")' 2>/dev/null)"
  if [ -z "$VERDICTS" ]; then
    printf '  \033[33m?\033[0m %s  no vendor statement for this package in the assessment — skipped\n' "$pkg"
    SKIP=$((SKIP + 1)); continue
  fi

  case ",$VERDICTS," in
    *,applicable,*)
      printf '  \033[32m=\033[0m %-28s kept — an applicable statement covers this release\n' "$pkg"
      KEEP=$((KEEP + 1)); continue ;;
  esac

  printf '  \033[31m-\033[0m %-28s reject — vendor scoped it to %s [%s]\n' "$pkg" "$product" "$VERDICTS"
  REJECT=$((REJECT + 1))
  case ",$VERDICTS," in
    *,not_applicable,*) MISMATCH=$((MISMATCH + 1)) ;;
    *)                  UNPLACEABLE=$((UNPLACEABLE + 1)) ;;
  esac
  [ "$APPLY" = "1" ] || continue

  if api -X POST -o /dev/null -H 'Content-Type: application/json' \
        --data "$(jq -nc --arg a "$ACTOR" '{actor_id: $a, actor_kind: "human"}')" \
        "$GOVERNANCE/api/v1/findings/$finding/proposals/$proposal/reject" >/dev/null 2>&1; then
    :
  else
    printf '      \033[31m✗\033[0m reject failed for %s\n' "$proposal"
    FAIL=$((FAIL + 1))
  fi
done <<< "$CANDIDATES"

printf '\n  reviewed %d · reject %d · kept %d · skipped %d\n' "$TOTAL" "$REJECT" "$KEEP" "$SKIP"
printf '  of the rejections: %d a KNOWN product mismatch, %d a scope Themis could not place\n' \
  "$MISMATCH" "$UNPLACEABLE"
if [ "$UNPLACEABLE" -gt 0 ]; then
  printf '  the second group is not a mismatch (D4) — read it on its own; a large count usually\n'
  printf '  means those Findings carry no rpm build that places the release.\n'
fi
if [ "$APPLY" = "1" ]; then
  printf '  written: %d rejected, %d failed\n' "$((REJECT - FAIL))" "$FAIL"
  printf '  a rejected proposal is RETAINED as history and establishes no Position;\n'
  printf '  every Finding stays open and in the queue.\n\n'
else
  printf '  nothing written — re-run with --apply to act\n\n'
fi
[ "$FAIL" -eq 0 ] || exit 1
