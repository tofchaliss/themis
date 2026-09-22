#!/usr/bin/env bash
# redhat-package-state-probe.sh — MEASURE whether Red Hat's per-CVE `package_state` discriminates
# the packages that CARRY a flaw from the packages a module-stream rebuild merely republished
# (EDR-ATTRIBUTION-01 D15, whose measurement D15 itself assigns to D13's step).
#
# THE QUESTION, AND WHY IT IS NARROW. An independent identity bridge is the only thing that could
# close the httpd cluster: NVD names carrier `http_server`, the estate runs `httpd`, and Themis
# refuses to guess between them (D7a — a CPE generated FROM the component name is not evidence
# about the component). Red Hat's `package_state` is a genuine candidate because it is Red Hat
# tracking THIS CVE against THAT package name — not derived from the customer's SBOM — and it
# already flows into Themis (only its `Not affected` entries, today, as VEX applicability).
#
# THE TRAP, and it is this whole arc's founding observation: a module-stream advisory rebuilds
# every RPM in the stream and publishes a fixed version for each. So "Red Hat shipped a fix for
# httpd" is NOT evidence that httpd carries the flaw — that is precisely the reading that turns a
# CPython flaw into a vulnerability of python3-pyyaml. The fixed-build list (`affected_release`)
# is the rebuild set. The question is whether the FLAW-SPECIFIC state (`package_state`, with its
# Affected / Not affected / Fix deferred) is a smaller, different thing, or the same set wearing
# different clothes.
#
# So, per CVE:
#     package_state distinct packages   vs   affected_release distinct packages
#   strictly fewer, and a subset  -> it discriminates; an authoritative bridge is already ingested
#   the same, or a superset       -> the same rebuild artifact, and D15 is answered NO
#
# STRICTLY READ-ONLY, and outbound only to the public Security Data API the Red Hat feed already
# uses. It changes nothing in Themis and consumes nothing from it but a list of CVE ids.
#
# WHAT IT CANNOT TELL YOU. Even a discriminating package_state is an RPM-world bridge: it can say
# nothing about a Maven, PyPI or npm component, and nothing about a distro Red Hat does not
# publish. And it names a package, not a version — a bridge for ATTRIBUTION, never for a verdict.
# Decide nothing from this script; it exists to answer one yes/no before anything is designed.
#
# Usage:
#   ./scripts/redhat-package-state-probe.sh CVE-2026-33006 CVE-2023-32681 ...
#   PGBASE="postgres://themis:PASSWORD@localhost:5432" ./scripts/redhat-package-state-probe.sh
#
# With no CVE arguments it takes the estate's own attribution-gap CVEs (up to $LIMIT, default 25)
# — the population D15 exists to serve. With arguments it probes exactly those and needs no
# database at all.
#
# Replay / test seam: PROBE_FIXTURE_DIR=<dir> reads <dir>/<CVE>.json instead of the network.
set -uo pipefail

BASE="${THEMIS_REDHAT_URL:-https://access.redhat.com/hydra/rest/securitydata}"
LIMIT="${LIMIT:-25}"
FIXTURES="${PROBE_FIXTURE_DIR:-}"

command -v jq >/dev/null || { echo "probe: jq is required" >&2; exit 2; }
[ -n "$FIXTURES" ] || command -v curl >/dev/null || { echo "probe: curl is required" >&2; exit 2; }

CVES=("$@")
if [ ${#CVES[@]} -eq 0 ]; then
  command -v psql >/dev/null || { echo "probe: psql is required to derive the gap population" >&2; exit 2; }
  if [ -z "${PGBASE:-}" ]; then
    echo "probe: pass CVE ids, or set PGBASE to take the estate's attribution-gap CVEs" >&2
    exit 2
  fi
  case "$LIMIT" in ''|*[!0-9]*) echo "probe: LIMIT must be a number" >&2; exit 2;; esac
  # The gap population, Governance-side: every active component scope-class. Ordered by component
  # count descending so the module-rebuild shapes — the ones the trap is about — come first.
  # read -r in a loop rather than mapfile: this has to run wherever the operator is, and macOS
  # ships bash 3.2, where mapfile does not exist.
  CVES=()
  while IFS= read -r line; do [ -n "$line" ] && CVES+=("$line"); done < <(psql "$PGBASE/governance?sslmode=disable" -Atc "
    select f.cve
      from findings f
      join finding_components c on c.finding_id = f.id
     where c.retired_at is null and f.cve <> ''
     group by f.id, f.cve
    having bool_and(c.claim_class = 'scope')
     order by count(*) desc
     limit $LIMIT" 2>/dev/null)
  [ ${#CVES[@]} -gt 0 ] || { echo "probe: no attribution-gap CVEs found" >&2; exit 1; }
  printf 'probe: taking %d attribution-gap CVE(s) from the estate\n' "${#CVES[@]}" >&2
fi

fetch() {
  if [ -n "$FIXTURES" ]; then cat "$FIXTURES/$1.json" 2>/dev/null; else curl -sf "$BASE/cve/$1.json" 2>/dev/null; fi
}

printf '\nRED HAT package_state PROBE (EDR-ATTRIBUTION-01 D15) — one measurement, no design\n'
printf '==================================================================================\n\n'
printf '%-18s %5s %5s %5s  %s\n' "CVE" "ps" "ar" "" "reading"
printf '%-18s %5s %5s %5s  %s\n' "" "pkgs" "pkgs" "sub?" ""

disc=0; enum=0; nops=0; nodoc=0; noar=0; total=0
for cve in "${CVES[@]}"; do
  [ -n "$cve" ] || continue
  total=$((total + 1))
  doc="$(fetch "$cve")"
  if [ -z "$doc" ]; then
    printf '%-18s %5s %5s %5s  %s\n' "$cve" "-" "-" "-" "no document (Red Hat tracks no such CVE, or fetch failed)"
    nodoc=$((nodoc + 1)); continue
  fi

  # package_state: the FLAW-SPECIFIC state, by distinct package name. Container and
  # layered-product artifacts (a "/" or ":" namespace, or a -container suffix) are excluded the
  # same way the feed ACL excludes them: an rpm/pypi/npm SBOM component never carries such a
  # name, so they can never bridge to anything installed.
  ps_names="$(printf '%s' "$doc" | jq -r '
      [ .package_state // [] | .[]
        | .package_name // ""
        | select(. != "" and (test("[/:]") | not) and (endswith("-container") | not)) ]
      | unique | .[]' 2>/dev/null)"
  # affected_release: the FIXED BUILD list = the rebuild set. Reduce each NEVRA to its package
  # name (strip -version-release), and a module id (name:stream) to its name.
  ar_names="$(printf '%s' "$doc" | jq -r '
      [ .affected_release // [] | .[]
        | .package // ""
        | select(. != "")
        | sub(":.*$"; "")
        | sub("-[0-9][^-]*-[^-]*$"; "")
        | sub("-[0-9][^-]*$"; "") ]
      | unique | .[]' 2>/dev/null)"

  nps=$(printf '%s' "$ps_names" | grep -c . || true)
  nar=$(printf '%s' "$ar_names" | grep -c . || true)

  if [ "$nps" -eq 0 ]; then
    printf '%-18s %5s %5s %5s  %s\n' "$cve" "0" "$nar" "-" "no package-level package_state — no bridge for this CVE"
    nops=$((nops + 1)); continue
  fi
  if [ "$nar" -eq 0 ]; then
    printf '%-18s %5s %5s %5s  %s\n' "$cve" "$nps" "0" "-" "package_state only, no rebuild set to compare against"
    noar=$((noar + 1)); continue
  fi

  # Subset test: is every flaw-specific package also in the rebuild set?
  extra="$(comm -23 <(printf '%s\n' "$ps_names" | sort -u) <(printf '%s\n' "$ar_names" | sort -u) | grep -c . || true)"
  sub="yes"; [ "$extra" -gt 0 ] && sub="no"
  if [ "$nps" -lt "$nar" ]; then
    disc=$((disc + 1))
    printf '%-18s %5s %5s %5s  %s\n' "$cve" "$nps" "$nar" "$sub" "FEWER than the rebuild set — discriminates here"
  else
    enum=$((enum + 1))
    printf '%-18s %5s %5s %5s  %s\n' "$cve" "$nps" "$nar" "$sub" "not fewer — enumerates the stream too"
  fi
  # The names themselves, because the counts are the question and the names are the evidence.
  printf '                   flaw-specific: %s\n' "$(printf '%s ' $ps_names | cut -c1-96)"
  printf '                   rebuild set  : %s\n' "$(printf '%s ' $ar_names | cut -c1-96)"
done

printf '\nSUMMARY over %d CVE(s)\n' "$total"
printf '  discriminates (package_state smaller than the rebuild set)  %4d\n' "$disc"
printf '  enumerates    (not smaller)                                 %4d\n' "$enum"
printf '  no package-level package_state                              %4d\n' "$nops"
printf '  no rebuild set to compare                                   %4d\n' "$noar"
printf '  no Red Hat document                                         %4d\n' "$nodoc"
printf '\nHOW TO READ IT. "discriminates" on most of the population means an authoritative,\n'
printf 'independent attribution bridge is ALREADY ingested and D15 becomes a design question.\n'
printf '"enumerates" means package_state is the same rebuild artifact in other clothing, D15 is\n'
printf 'answered NO, and the httpd cluster stays exactly where D5 left it — which is a real\n'
printf 'answer and costs nothing but this run.\n'
printf '\nEither way this script decides NOTHING. It is RPM-world only, it names packages and not\n'
printf 'versions, and a bridge would still have to be designed, grilled and measured on its own.\n\n'
