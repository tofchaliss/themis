# Operational Actions — outstanding, owner-held

Actions a **human operator** must take on the running deployment. They are NOT architecture work and they
do not belong in [`docs/BACKLOG.md`](BACKLOG.md): that file tracks what the codebase owes, and an item
here is owed by whoever holds the credentials and the machine.

Kept separate because an operational item buried among architecture entries reads as "someday". These do
not become less urgent by being written down.

---

## ✎ RECORDED — 138 vendor-VEX rejections carry a placeholder decider (2026-09-21)

**Not an action — a provenance note, kept here because the audit trail itself cannot be corrected.**

On 2026-09-21 the 138 standing vendor-VEX `not_affected` proposals that rested on statements scoped to
products this estate does not run were rejected via `scripts/vex-reject-inapplicable.sh --apply`. The
command was pasted with its example actor intact, so all 138 are recorded with
`decided_id = your.name@example.com`.

**What is sound:** the decisions. Each rejection is reproducible from the Governance assessment
projection plus the script's rule (reject only when no statement covering the package is `applicable`),
and the dry run was read before applying. No Finding was suppressed, no Position was established, and
all 138 Findings remain open and in the queue.

**What is wrong:** the decider field only. Proposals are append-only, so there is no edit path, and a
rejected proposal cannot be re-raised under the same `(finding, package)` id — there is no clean redo.

**Why it is written down rather than fixed:** correcting `decided_id` means an `UPDATE` against an
append-only audit record, bypassing the event stream this architecture treats as the authoritative
mutation path. That trade is the owner's to make, not a cleanup to perform quietly. This note is the
truthful external reference in the meantime.

**The underlying gap is filed as `DEF_GOV_DECIDER_UNVERIFIED`** in [`BACKLOG.md`](BACKLOG.md): the
recorded decider is free text with no relation to the authenticated caller, even though
`internal/platform/auth` already carries a principal its own comment calls "the auditable principal id".

---

## ⚠ OPEN — Rotate the exposed PostgreSQL credential

**Raised 2026-09-16. Open across FOUR sessions (2026-09-16, 2026-09-17, 2026-09-18, 2026-09-21). Blocks nothing; fixes itself
never.**

**What happened.** A command written in `fish` syntax was pasted into a `bash` shell:
`set -x RELS "…"`. In bash that sets nothing — it enables **xtrace** and makes the rest positional
parameters. Every subsequent command was echoed, and the DSN in `$PGBASE` printed the PostgreSQL password
to the terminal.

**Where the exposure lives.**

- Terminal scrollback on the operator workstation.
- The shell history file — the prompt in use runs `history -a`, so it was written to disk, not just held
  in memory.
- Any terminal-session capture or log that recorded the pasted output.

**What to do.**

1. Rotate the `themis` role's password on the PostgreSQL server.
2. Rewrite the DSN in each of the six `/etc/themis/<svc>.env` files (registry, evidence, knowledge,
   governance, communication, intelligence) plus the dashboard's.
   **Use explicit paths, not a glob.** `/etc/themis` is not listable by an unprivileged user, so a
   shell glob like `/etc/themis/*.env` is **not expanded** and is passed to the command literally,
   which then reports `No such file or directory` — for files that exist and are loaded. Verified
   2026-09-21: `systemctl show themis@governance -p EnvironmentFiles` reports
   `/etc/themis/governance.env (ignore_errors=no)` on a node that is active, so the file must
   exist. Confirm the real path per service with
   `systemctl cat themis@<svc> | grep EnvironmentFile` before editing anything, and never read a
   missing-file error from a glob as evidence that the runbook is wrong.
3. Restart all six nodes and the dashboard.
4. Purge the password from shell history (`history -c` plus the on-disk history file) and clear
   scrollback.

**One non-obvious hazard, worth reading before step 1.** `pgx` pools keep serving on connections opened
BEFORE a password change, so **every node will report healthy on a credential that no longer works**, and
they then all fail together at the next restart — at a moment nobody chose. Restart the fleet deliberately
in step 3 rather than discovering this later. This is the same mechanism that hid the 2026-08-08 drift for
days; see `DB-password rotation orchestration` in the backlog for the tooling that would make step 2
atomic, which is the engineering half of this and is tracked there, correctly.

**Why it has not been done for you.** `scripts/vm-verify.sh` is read-only by design — mutations stay in a
human's hands — and the deployment VM is not reachable from the assistant's environment. Every other item
from these sessions could be shipped as code; this one cannot.
