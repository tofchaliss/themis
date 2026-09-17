# Operational Actions — outstanding, owner-held

Actions a **human operator** must take on the running deployment. They are NOT architecture work and they
do not belong in [`docs/BACKLOG.md`](BACKLOG.md): that file tracks what the codebase owes, and an item
here is owed by whoever holds the credentials and the machine.

Kept separate because an operational item buried among architecture entries reads as "someday". These do
not become less urgent by being written down.

---

## ⚠ OPEN — Rotate the exposed PostgreSQL credential

**Raised 2026-09-16. Open across three sessions (2026-09-16, 2026-09-17). Blocks nothing; fixes itself
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
