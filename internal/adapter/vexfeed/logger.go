package vexfeed

import (
	"github.com/themis-project/themis/internal/domain"
)

// LoggerMismatch logs purl_mismatch events through the unified domain logging
// port (CR-7) instead of slog.Default().
type LoggerMismatch struct {
	Log domain.Logger
}

func (l LoggerMismatch) LogPURLMismatch(cveID, sbomPURL, vexPURL string) {
	domain.LoggerOrNop(l.Log).Info("upstream vex purl mismatch",
		domain.LogString("cve_id", cveID),
		domain.LogString("sbom_purl", sbomPURL),
		domain.LogString("vex_purl", vexPURL),
	)
}

// LoggerSync bridges the vexfeed SyncLogger (zap-sugar key/value variadic) to the
// domain logging port, so per-feed-line fetch failures finally surface (the
// SyncLogger was previously defaulted to NoOp and never wired — D-LOG-1).
type LoggerSync struct {
	Log domain.Logger
}

// Warn logs a vendor feed warning with paired key/value fields.
func (l LoggerSync) Warn(msg string, fields ...any) {
	domain.LoggerOrNop(l.Log).Warn(msg, pairsToFields(fields)...)
}

// Error logs a vendor feed error with paired key/value fields.
func (l LoggerSync) Error(msg string, fields ...any) {
	domain.LoggerOrNop(l.Log).Error(msg, pairsToFields(fields)...)
}

func pairsToFields(args []any) []domain.Field {
	out := make([]domain.Field, 0, len(args)/2)
	for i := 0; i+1 < len(args); i += 2 {
		key, _ := args[i].(string)
		out = append(out, domain.LogAny(key, args[i+1]))
	}
	return out
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
