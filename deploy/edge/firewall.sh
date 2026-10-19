#!/usr/bin/env bash
# Themis host firewall (VM-NET-1): allow SSH and HTTPS, nothing else inbound.
#
# The six API nodes and the dashboard bind to loopback (see INSTALLATION.md §7a), so the only
# inbound services a Themis host offers are SSH and the TLS edge on 443. This script makes the
# host firewall say exactly that, with firewalld (Rocky/RHEL) or ufw (Ubuntu/Debian), whichever
# the host has. It is DRY-RUN by default: it prints the commands it would run and the current
# state; pass --apply to run them. SSH is allowed before anything is denied, so an SSH session
# running the script survives it.
set -euo pipefail

APPLY=0
[[ "${1:-}" == "--apply" ]] && APPLY=1

run() {
  if [[ "$APPLY" == "1" ]]; then
    "$@"
  else
    printf 'would run: %q ' "$@"; echo
  fi
}

if command -v firewall-cmd >/dev/null 2>&1; then
  run systemctl enable --now firewalld
  run firewall-cmd --permanent --set-default-zone=public
  run firewall-cmd --permanent --zone=public --add-service=ssh
  run firewall-cmd --permanent --zone=public --add-service=https
  # Nothing below is opened: 8081-8086 (API nodes), 8090 (dashboard), 5432 (Postgres) stay on
  # loopback and are reachable only through the TLS edge or on the host itself.
  run firewall-cmd --permanent --zone=public --remove-service=http || true
  for port in 8081 8082 8083 8084 8085 8086 8090 5432; do run firewall-cmd --permanent --zone=public --remove-port="${port}/tcp" || true; done
  run firewall-cmd --reload
  if [[ "$APPLY" == "1" ]]; then firewall-cmd --zone=public --list-all; else echo; echo "dry run only; re-run with --apply. Current zone:"; firewall-cmd --zone=public --list-all 2>/dev/null || echo "(firewalld not running)"; fi
elif command -v ufw >/dev/null 2>&1; then
  run ufw allow OpenSSH
  run ufw allow 443/tcp
  run ufw default deny incoming
  run ufw default allow outgoing
  for port in 8081 8082 8083 8084 8085 8086 8090 5432; do run ufw delete allow "${port}/tcp" || true; done
  run ufw --force enable
  if [[ "$APPLY" == "1" ]]; then ufw status verbose; else echo; echo "dry run only; re-run with --apply. Current state:"; ufw status verbose 2>/dev/null || echo "(ufw not active)"; fi
else
  echo "neither firewall-cmd (firewalld) nor ufw found: install one (dnf install firewalld / apt-get install ufw) or write the equivalent for your firewall." >&2
  exit 2
fi
