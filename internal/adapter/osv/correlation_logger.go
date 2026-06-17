package osv

import (
	"log/slog"
)

// CorrelationLogger records OSV correlation skip and mismatch events.
type CorrelationLogger interface {
	LogUnsupportedEcosystem(purl, ecosystem, name, version string)
	LogMalformedPURL(purl, ecosystem, name, version, reason string)
	LogIdentityMismatch(purl, ecosystem, name, version, osvPkg, cveID string)
	LogVersionNoMatch(purl, ecosystem, name, version, cveID string)
	LogSkipSummary(counts map[string]int)
}

// NoOpCorrelationLogger ignores correlation logs.
type NoOpCorrelationLogger struct{}

func (NoOpCorrelationLogger) LogUnsupportedEcosystem(string, string, string, string) {}
func (NoOpCorrelationLogger) LogMalformedPURL(string, string, string, string, string) {
}
func (NoOpCorrelationLogger) LogIdentityMismatch(string, string, string, string, string, string) {
}
func (NoOpCorrelationLogger) LogVersionNoMatch(string, string, string, string, string) {}
func (NoOpCorrelationLogger) LogSkipSummary(map[string]int)                            {}

// SlogCorrelationLogger logs correlation events via slog.
type SlogCorrelationLogger struct {
	Logger *slog.Logger
}

func (l SlogCorrelationLogger) log() *slog.Logger {
	if l.Logger != nil {
		return l.Logger
	}
	return slog.Default()
}

func (l SlogCorrelationLogger) LogUnsupportedEcosystem(purl, ecosystem, name, version string) {
	l.log().Debug("osv correlation skip",
		"reason", "unsupported_ecosystem", "purl", purl, "ecosystem", ecosystem, "name", name, "version", version)
}

func (l SlogCorrelationLogger) LogMalformedPURL(purl, ecosystem, name, version, reason string) {
	l.log().Warn("osv correlation skip",
		"reason", reason, "purl", purl, "ecosystem", ecosystem, "name", name, "version", version)
}

func (l SlogCorrelationLogger) LogIdentityMismatch(purl, ecosystem, name, version, osvPkg, cveID string) {
	l.log().Debug("osv correlation skip",
		"reason", "identity_mismatch", "purl", purl, "ecosystem", ecosystem, "name", name,
		"version", version, "osv_package", osvPkg, "cve_id", cveID)
}

func (l SlogCorrelationLogger) LogVersionNoMatch(purl, ecosystem, name, version, cveID string) {
	l.log().Debug("osv correlation skip",
		"reason", "version_no_match", "purl", purl, "ecosystem", ecosystem, "name", name,
		"version", version, "cve_id", cveID)
}

func (l SlogCorrelationLogger) LogSkipSummary(counts map[string]int) {
	if len(counts) == 0 {
		return
	}
	l.log().Info("osv correlation skip summary", "ecosystems", counts)
}

// CaptureCorrelationLogger records correlation events for tests.
type CaptureCorrelationLogger struct {
	Unsupported   int
	Malformed     []string
	Identity      int
	Version       int
	SummaryCounts map[string]int
}

func (l *CaptureCorrelationLogger) LogUnsupportedEcosystem(string, string, string, string) {
	l.Unsupported++
}

func (l *CaptureCorrelationLogger) LogMalformedPURL(_ string, _ string, _ string, _ string, reason string) {
	l.Malformed = append(l.Malformed, reason)
}

func (l *CaptureCorrelationLogger) LogIdentityMismatch(string, string, string, string, string, string) {
	l.Identity++
}

func (l *CaptureCorrelationLogger) LogVersionNoMatch(string, string, string, string, string) {
	l.Version++
}

func (l *CaptureCorrelationLogger) LogSkipSummary(counts map[string]int) {
	l.SummaryCounts = counts
}
