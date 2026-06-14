package vexfeed

import (
	"log/slog"
)

// SlogMismatchLogger logs purl_mismatch at INFO with structured fields.
type SlogMismatchLogger struct {
	Logger *slog.Logger
}

func (l SlogMismatchLogger) LogPURLMismatch(cveID, sbomPURL, vexPURL string) {
	logger := l.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Info("upstream vex purl mismatch",
		slog.String("cve_id", cveID),
		slog.String("sbom_purl", sbomPURL),
		slog.String("vex_purl", vexPURL),
	)
}

// CaptureMismatchLogger records mismatches for tests.
type CaptureMismatchLogger struct {
	Entries []MismatchEntry
}

type MismatchEntry struct {
	CVEID    string
	SBOMPURL string
	VEXPURL  string
}

func (l *CaptureMismatchLogger) LogPURLMismatch(cveID, sbomPURL, vexPURL string) {
	l.Entries = append(l.Entries, MismatchEntry{
		CVEID: cveID, SBOMPURL: sbomPURL, VEXPURL: vexPURL,
	})
}
