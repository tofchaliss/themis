-- KN-RECOR-1: the re-discovery ledger. Knowledge remembers which (release, evidence) pairs it
-- has correlated and when discovery last ran for each, so a scheduled sweep can re-ask the
-- discovery feeds about the stalest inventories — closing the static-estate blind spot where a
-- CVE published after a release's last upload was invisible until the next upload.
--
-- One row per release, holding the LATEST correlated evidence id: a newer SBOM for the same
-- release replaces it, so the sweep always re-reads the current inventory. No backfill — a
-- pre-migration release enters the ledger on its next upload; until then it is exactly as
-- visible as it was.
CREATE TABLE IF NOT EXISTS correlated_releases (
    release_id         TEXT PRIMARY KEY,
    evidence_id        TEXT NOT NULL,
    last_discovered_at TIMESTAMPTZ NOT NULL
);
