#!/usr/bin/env bash
# Themis host firewall (VM-NET-1): allow SSH and HTTPS, nothing else inbound.
#
# The six API nodes and the dashboard bind to loopback (see INSTALLATION.md §7a), so the only
# inbound services a Themis host offers are SSH and the TLS edge on 443. This script makes
# firewalld say exactly that. It is DRY-RUN by default: it prints the commands it would run and
# the resulting zone; pass --apply to run them. It refuses on a host without firewalld rather
# than guessing at a different firewall.
set -euo pipefail

APPLY=0
[[ "${1:-}" == "--apply" ]] && APPLY=1

if ! command -v firewall-cmd >/dev/null 2>&1; then
  echo "firewall-cmd not found: this script targets firewalld (Rocky/RHEL). Install it (dnf install firewalld; systemctl enable --now firewalld) or write the equivalent for your firewall." >&2
  exit 2
fi

run() {
  if [[ "$APPLY" == "1" ]]; then
    "$@"
  else
    printf 'would run: %q ' "$@"; echo
  fi
}

run systemctl enable --now firewalld
run firewall-cmd --permanent --set-default-zone=public
run firewall-cmd --permanent --zone=public --add-service=ssh
run firewall-cmd --permanent --zone=public --add-service=https
# Nothing below is opened: 8081-8086 (API nodes), 8090 (dashboard), 5432 (Postgres) stay on
# loopback and are reachable only through the TLS edge or on the host itself.
for svc in http; do run firewall-cmd --permanent --zone=public --remove-service="$svc" || true; done
for port in 8081 8082 8083 8084 8085 8086 8090 5432; do run firewall-cmd --permanent --zone=public --remove-port="${port}/tcp" || true; done
run firewall-cmd --reload

if [[ "$APPLY" == "1" ]]; then
  firewall-cmd --zone=public --list-all
else
  echo
  echo "dry run only; re-run with --apply to change the firewall. Current zone:"
  firewall-cmd --zone=public --list-all 2>/dev/null || echo "(firewalld not running)"
fi
