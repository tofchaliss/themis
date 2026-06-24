package osv

import (
	"github.com/themis-project/themis/internal/domain"
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

// LoggerCorrelation logs correlation skip/mismatch events through the unified
// domain logging port (CR-7) rather than slog.Default(). Skip events are
// debug-level (high volume), malformed purls warn, and the per-cycle skip
// summary is info — all governed by THEMIS_LOG_LEVEL through one backend.
type LoggerCorrelation struct {
	Log domain.Logger
}

func (l LoggerCorrelation) log() domain.Logger { return domain.LoggerOrNop(l.Log) }

func (l LoggerCorrelation) LogUnsupportedEcosystem(purl, ecosystem, name, version string) {
	l.log().Debug("osv correlation skip",
		domain.LogString("reason", "unsupported_ecosystem"), domain.LogString("purl", purl),
		domain.LogString("ecosystem", ecosystem), domain.LogString("name", name), domain.LogString("version", version))
}

func (l LoggerCorrelation) LogMalformedPURL(purl, ecosystem, name, version, reason string) {
	l.log().Warn("osv correlation skip",
		domain.LogString("reason", reason), domain.LogString("purl", purl),
		domain.LogString("ecosystem", ecosystem), domain.LogString("name", name), domain.LogString("version", version))
}

func (l LoggerCorrelation) LogIdentityMismatch(purl, ecosystem, name, version, osvPkg, cveID string) {
	l.log().Debug("osv correlation skip",
		domain.LogString("reason", "identity_mismatch"), domain.LogString("purl", purl),
		domain.LogString("ecosystem", ecosystem), domain.LogString("name", name),
		domain.LogString("version", version), domain.LogString("osv_package", osvPkg), domain.LogString("cve_id", cveID))
}

func (l LoggerCorrelation) LogVersionNoMatch(purl, ecosystem, name, version, cveID string) {
	l.log().Debug("osv correlation skip",
		domain.LogString("reason", "version_no_match"), domain.LogString("purl", purl),
		domain.LogString("ecosystem", ecosystem), domain.LogString("name", name),
		domain.LogString("version", version), domain.LogString("cve_id", cveID))
}

func (l LoggerCorrelation) LogSkipSummary(counts map[string]int) {
	if len(counts) == 0 {
		return
	}
	l.log().Info("osv correlation skip summary", domain.LogAny("ecosystems", counts))
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
