CREATE TABLE epss_kev_signals (
    cve_id TEXT PRIMARY KEY,
    epss_score NUMERIC(6, 5),
    kev_listed BOOLEAN NOT NULL DEFAULT FALSE,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    stale BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_epss_kev_signals_kev_listed ON epss_kev_signals (kev_listed);
