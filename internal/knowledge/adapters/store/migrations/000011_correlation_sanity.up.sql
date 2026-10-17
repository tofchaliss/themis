-- KN-SANITY-1 (2026-10-17): the fan-out guard's flags. One row per (release, component purl):
-- a feed answered a version Themis cannot parse with at least N distinct CVEs — the shape that
-- opened 165 Go CVEs on one component in October 2026 and was visible all along. The guard
-- measures and names; it drops nothing and decides nothing. Rows are overwritten on re-flag.
CREATE TABLE IF NOT EXISTS correlation_sanity (
    release_id   TEXT        NOT NULL,
    purl         TEXT        NOT NULL,
    version      TEXT        NOT NULL DEFAULT '',
    ecosystem    TEXT        NOT NULL DEFAULT '',
    cves         INT         NOT NULL,
    reason       TEXT        NOT NULL,
    flagged_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (release_id, purl)
);
