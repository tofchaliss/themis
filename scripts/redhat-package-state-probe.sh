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
# AND THE QUESTION THAT ACTUALLY DECIDES IT (added 2026-09-22, after the first run). "Smaller than
# the rebuild set" is necessary and NOT sufficient. Measured on this estate: package_state is
# smaller on 24 of 25 CVEs, but most of those sets are not SUBSETS — it names `python`, `python2.7`
# and `python3.9` where the rebuild set carries `python39` and `rh-python38-python`. Flaw-specific,
# certainly; in a DIFFERENT VOCABULARY, also certainly. A bridge has to land on the name the
# estate actually installed, so with a database this now asks, per gap Finding:
#
#   BRIDGE   the installed component name appears in package_state
#            -> Red Hat attributes the flaw to the very thing installed. The gap would close.
#   REBUILD  it appears ONLY in the rebuild set
#            -> positive evidence it is a rebuild member, not a carrier. The trap, confirmed.
#   NEITHER  it appears in neither
#            -> package_state speaks a vocabulary that does not reach this component; no bridge.
#
# NEITHER is the outcome that kills the idea, and REBUILD is the outcome that is worth more than
# a bridge: it is evidence for the scope classification Themis already made.
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
# Replay / test seam: PROBE_FIXTURE_DIR=<dir> reads <dir>/<CVE>.json instead of the network, and
# INSTALLED_TSV=<file> (rows of "CVE<TAB>component names") supplies the installed side without a
# database. Both were used to exercise the bridge logic before it ever ran against an estate.
set -uo pipefail

BASE="${THEMIS_REDHAT_URL:-https://access.redhat.com/hydra/rest/securitydata}"
LIMIT="${LIMIT:-25}"
FIXTURES="${PROBE_FIXTURE_DIR:-}"

command -v jq >/dev/null || { echo "probe: jq is required" >&2; exit 2; }
[ -n "$FIXTURES" ] || command -v curl >/dev/null || { echo "probe: curl is required" >&2; exit 2; }

CVES=("$@")
# The installed side is derived whenever a database is reachable, EVEN WITH EXPLICIT CVE
# ARGUMENTS: the bridge question is the one that decides D15, and asking it only on the default
# population would leave every targeted run unable to answer it.
if [ -n "${PGBASE:-}" ] && command -v psql >/dev/null; then
  INSTALLED_TSV="$(mktemp)"
  trap 'rm -f "$INSTALLED_TSV"' EXIT
  psql "$PGBASE/governance?sslmode=disable" -At -F $'\t' -c "
    select f.cve, string_agg(distinct c.name, ' ')
      from findings f
      join finding_components c on c.finding_id = f.id
     where c.retired_at is null and c.name <> '' and f.cve <> ''
     group by f.id, f.cve
    having bool_and(c.claim_class = 'scope')" > "$INSTALLED_TSV" 2>/dev/null
fi

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
  # STRATIFIED by fan-out, half from each end, and this is not a refinement — it is a correction.
  # Ordering by fan-out DESCENDING (the first version) samples only the module-rebuild sets and
  # never reaches the single-component gaps, which are 68% of the population and include the whole
  # httpd cluster this question was raised for. Measured 2026-09-22: that biased sample returned
  # 25 of 25 NEITHER and would have answered D15 "no" without ever probing the case D15 is about.
  # A sample that can only see one shape cannot answer a question about which shapes exist.
  half=$(( LIMIT / 2 )); [ "$half" -lt 1 ] && half=1
  CVES=()
  while IFS= read -r line; do [ -n "$line" ] && CVES+=("$line"); done < <(psql "$PGBASE/governance?sslmode=disable" -Atc "
    (select f.cve from findings f join finding_components c on c.finding_id = f.id
      where c.retired_at is null and f.cve <> ''
      group by f.id, f.cve having bool_and(c.claim_class = 'scope')
      order by count(*) desc limit $half)
    union
    (select f.cve from findings f join finding_components c on c.finding_id = f.id
      where c.retired_at is null and f.cve <> ''
      group by f.id, f.cve having bool_and(c.claim_class = 'scope')
      order by count(*) asc limit $half)" 2>/dev/null)
  [ ${#CVES[@]} -gt 0 ] || { echo "probe: no attribution-gap CVEs found" >&2; exit 1; }
  printf 'probe: taking %d attribution-gap CVE(s) from the estate (stratified by fan-out)\n' "${#CVES[@]}" >&2
fi

fetch() {
  if [ -n "$FIXTURES" ]; then cat "$FIXTURES/$1.json" 2>/dev/null; else curl -sf "$BASE/cve/$1.json" 2>/dev/null; fi
}

printf '\nRED HAT package_state PROBE (EDR-ATTRIBUTION-01 D15) — one measurement, no design\n'
printf '==================================================================================\n\n'
printf '%-18s %5s %5s %5s  %s\n' "CVE" "ps" "ar" "" "reading"
printf '%-18s %5s %5s %5s  %s\n' "" "pkgs" "pkgs" "sub?" ""

installed_for() {
  [ -n "${INSTALLED_TSV:-}" ] || return 0
  awk -F'\t' -v c="$1" '$1 == c { print $2; exit }' "$INSTALLED_TSV"
}

disc=0; enum=0; nops=0; nodoc=0; noar=0; total=0
bridge=0; rebuild=0; neither=0
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

  # THE BRIDGE QUESTION, asked only when the estate is available: does either list name what is
  # actually installed on the gap this CVE belongs to?
  inst="$(installed_for "$cve")"
  if [ -n "$inst" ]; then
    hit=""; reb=""
    for name in $inst; do
      printf '%s\n' "$ps_names" | grep -qix -- "$name" && hit="$hit $name"
      printf '%s\n' "$ar_names" | grep -qix -- "$name" && reb="$reb $name"
    done
    if [ -n "$hit" ]; then
      bridge=$((bridge + 1));  printf '                   BRIDGE : package_state names the installed%s\n' "$hit"
    elif [ -n "$reb" ]; then
      rebuild=$((rebuild + 1)); printf '                   REBUILD: installed appears only in the rebuild set%s — evidence of scope, not carrier\n' "$reb"
    else
      neither=$((neither + 1)); printf '                   NEITHER: installed (%s) appears in neither list\n' "$(printf '%s ' $inst | cut -c1-60)"
    fi
  fi
done

printf '\nSUMMARY over %d CVE(s)\n' "$total"
printf '  discriminates (package_state smaller than the rebuild set)  %4d\n' "$disc"
printf '  enumerates    (not smaller)                                 %4d\n' "$enum"
printf '  no package-level package_state                              %4d\n' "$nops"
printf '  no rebuild set to compare                                   %4d\n' "$noar"
printf '  no Red Hat document                                         %4d\n' "$nodoc"
if [ $((bridge + rebuild + neither)) -gt 0 ]; then
  printf '\nTHE BRIDGE QUESTION (gap Findings whose installed component was checked)\n'
  printf '  BRIDGE  package_state names the installed component            %4d\n' "$bridge"
  printf '  REBUILD installed appears only in the rebuild set              %4d\n' "$rebuild"
  printf '  NEITHER installed appears in neither list                      %4d\n' "$neither"
  printf '  A high BRIDGE count is the only result that makes D15 a design question. REBUILD is\n'
  printf '  positive evidence for the scope classification Themis already made. NEITHER means the\n'
  printf '  flaw-specific list speaks a vocabulary that never reaches this estate.\n'
fi
printf '\nHOW TO READ IT. "discriminates" on most of the population means an authoritative,\n'
printf 'independent attribution bridge is ALREADY ingested and D15 becomes a design question.\n'
printf '"enumerates" means package_state is the same rebuild artifact in other clothing, D15 is\n'
printf 'answered NO, and the httpd cluster stays exactly where D5 left it — which is a real\n'
printf 'answer and costs nothing but this run.\n'
printf '\nEither way this script decides NOTHING. It is RPM-world only, it names packages and not\n'
printf 'versions, and a bridge would still have to be designed, grilled and measured on its own.\n\n'
