package vexfeed

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/themis-project/themis/internal/domain"
)

// CR-4 — distro feeds as correlation sources.
//
// Alpine/Rocky/Wolfi OSV feeds are vulnerability databases (affected ranges +
// fixed version + severity), not exploitability VEX. They used to be forced into
// the VEX overlay, which discarded their severity and made version-range math
// masquerade as a vendor verdict. Here they back a domain.CorrelationSource: an
// in-memory index of parsed assertions answering per-component queries through
// the single Correlator (CR-2), with proper provenance (CR-3) and the unified
// version engine (CR-1). The VEX overlay now carries only true vendor VEX.

// AssertionCorrelationSource serves correlation findings from an in-memory index
// of distro vulnerability-DB assertions. It is safe for concurrent reads while a
// background loader swaps the index.
type AssertionCorrelationSource struct {
	name  string
	mu    sync.RWMutex
	index map[string][]domain.VendorVEXAssertion
}

var _ domain.CorrelationSource = (*AssertionCorrelationSource)(nil)

// NewAssertionCorrelationSource creates an empty source with the given provenance
// fallback name.
func NewAssertionCorrelationSource(name string) *AssertionCorrelationSource {
	return &AssertionCorrelationSource{name: name, index: map[string][]domain.VendorVEXAssertion{}}
}

// Name is the provenance fallback label (records carry a per-feed source class).
func (s *AssertionCorrelationSource) Name() string { return s.name }

// Load atomically replaces the index with assertions keyed by version class and
// normalized package name. Rangeless assertions (no introduced and no fixed) are
// dropped — without a bound they would match every version (over-match).
func (s *AssertionCorrelationSource) Load(assertions []domain.VendorVEXAssertion) {
	index := make(map[string][]domain.VendorVEXAssertion)
	for _, a := range assertions {
		if a.Introduced == "" && a.Fixed == "" {
			continue
		}
		pkg := a.PackageName
		if pkg == "" {
			continue
		}
		key := assertionKeyFor(a.Ecosystem, pkg)
		index[key] = append(index[key], a)
	}
	s.mu.Lock()
	s.index = index
	s.mu.Unlock()
}

// FetchForComponent returns findings for assertions whose package matches the
// component and whose affected range covers the installed version (CR-1 engine).
func (s *AssertionCorrelationSource) FetchForComponent(_ context.Context, component domain.CanonicalComponent) ([]domain.VulnerabilityRecord, error) {
	key := assertionKeyFor(component.Ecosystem, component.Name)
	s.mu.RLock()
	matches := s.index[key]
	s.mu.RUnlock()
	if len(matches) == 0 {
		return nil, nil
	}

	compStream := domain.RPMReleaseMajor(component.Version)

	var out []domain.VulnerabilityRecord
	for _, a := range matches {
		// Release-stream guard: RPM maintenance streams are independent, so an
		// el8 package is never fixed by an el9 build. Reject assertions from a
		// different stream before the version compare — otherwise "6.1.el8" <
		// "6.2.el9" reads as affected (a cross-stream false positive). An unknown
		// stream on either side falls through to the version math (no false
		// negatives), so apk and tag-less RPM versions are unaffected.
		if compStream != "" {
			asrtStream := domain.RPMReleaseMajor(a.Ecosystem)
			if asrtStream == "" {
				asrtStream = domain.RPMReleaseMajor(a.Fixed)
			}
			if asrtStream == "" {
				asrtStream = domain.RPMReleaseMajor(a.Introduced)
			}
			if asrtStream != "" && asrtStream != compStream {
				continue
			}
		}
		group := domain.BuildConstraintGroup(a.Introduced, "", "", a.Fixed)
		affected := []string{group}
		if group == "" {
			affected = []string{"*"} // introduced "0"/absent with no fix → all versions
		}
		if !domain.VersionMatchesEco(component.Ecosystem, affected, component.Version) {
			continue
		}
		fixes := []string(nil)
		if a.Fixed != "" {
			fixes = []string{a.Fixed}
		}
		out = append(out, domain.VulnerabilityRecord{
			CVEID:            a.CVEID,
			Severity:         a.Severity,
			CVSSScore:        a.CVSSScore,
			CVSSVector:       a.CVSSVector,
			Ecosystem:        component.Ecosystem,
			PackageName:      component.Name,
			AffectedVersions: affected,
			FixVersions:      fixes,
			Source:           feedClassToSource(a.Feed),
		})
	}
	return out, nil
}

// assertionKeyFor groups a package by version class + normalized name so apk
// components match Alpine/Wolfi assertions and rpm components match Rocky/RHEL.
func assertionKeyFor(ecosystem, packageName string) string {
	return string(domain.ClassifyEcosystem(ecosystem)) + "|" + normalizeAssertionName(packageName)
}

// normalizeAssertionName lowercases and drops any namespace prefix
// (e.g. "alpine/busybox" → "busybox") so SBOM and feed package names align.
func normalizeAssertionName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	return name
}

// feedClassToSource maps a feed name to its finding-source provenance class.
func feedClassToSource(feed string) string {
	switch strings.ToLower(strings.TrimSpace(feed)) {
	case "rhel", "rhsa", "redhat", "rhel_csaf":
		return domain.FindingSourceRHSA
	default:
		return domain.FindingSourceDistroOSV
	}
}

// CorrelationLoader fetches the configured distro feeds and rebuilds the
// correlation source's index. It runs at startup and on the feed poll interval.
type CorrelationLoader struct {
	Feeds  []FeedSource
	Source *AssertionCorrelationSource
	Logger domain.Logger
}

// Refresh fetches all feeds, aggregates their assertions, and loads the index.
// A failing feed is logged and skipped; surviving feeds still load. It returns an
// error only when every attempted feed failed, so the scheduler can mark the
// aggregate distro-correlation feed degraded.
func (l *CorrelationLoader) Refresh(ctx context.Context) error {
	log := domain.LoggerOrNop(l.Logger)
	var all []domain.VendorVEXAssertion
	attempted, failures := 0, 0
	for _, feed := range l.Feeds {
		if feed == nil {
			continue
		}
		attempted++
		assertions, err := feed.Fetch(ctx)
		if err != nil {
			failures++
			log.Warn("distro correlation feed fetch failed",
				domain.LogString("feed", feed.Name()), domain.LogErr(err))
			continue
		}
		all = append(all, assertions...)
	}
	l.Source.Load(all)
	if attempted > 0 && failures == attempted {
		return fmt.Errorf("all %d distro correlation feeds failed", attempted)
	}
	log.Info("distro correlation feeds loaded",
		domain.LogInt("assertions", len(all)), domain.LogInt("feeds", attempted))
	return nil
}
