package osv

import (
	"context"

	"github.com/themis-project/themis/internal/domain"
)

// ComponentFetcher queries OSV when the local vulnerability cache has no matches.
type ComponentFetcher struct {
	Client     *Client
	Logger     CorrelationLogger
	skipCounts map[string]int
}

// Name is the provenance label for OSV.dev-correlated findings (domain.CorrelationSource).
func (f *ComponentFetcher) Name() string { return domain.FindingSourceOSV }

// EmitCorrelationSummary flushes deferred skip summaries (implements domain.CorrelationSummaryEmitter).
func (f *ComponentFetcher) EmitCorrelationSummary() {
	logger := f.Logger
	if logger == nil {
		logger = NoOpCorrelationLogger{}
	}
	if len(f.skipCounts) > 0 {
		logger.LogSkipSummary(f.skipCounts)
	}
	f.skipCounts = nil
}

// FetchForComponent returns CVE records affecting the component from OSV.
func (f *ComponentFetcher) FetchForComponent(ctx context.Context, component domain.CanonicalComponent) ([]domain.VulnerabilityRecord, error) {
	logger := f.Logger
	if logger == nil {
		logger = NoOpCorrelationLogger{}
	}
	purl := component.PURL
	if component.Name == "" {
		logger.LogMalformedPURL(purl, component.Ecosystem, component.Name, component.Version, "malformed_purl")
		return nil, nil
	}
	if _, ok := MapEcosystem(component.Ecosystem); !ok {
		logger.LogUnsupportedEcosystem(purl, component.Ecosystem, component.Name, component.Version)
		if f.skipCounts == nil {
			f.skipCounts = map[string]int{}
		}
		f.skipCounts[component.Ecosystem]++
		return nil, nil
	}
	if f.Client == nil {
		return nil, nil
	}
	queryName := normalizePackageName(component.Ecosystem, component.Name)
	feed, err := f.Client.QueryByEcosystem(ctx, component.Ecosystem, []domain.OSVPackageQuery{{Name: queryName}})
	if err != nil {
		return nil, err
	}
	var out []domain.VulnerabilityRecord
	for _, item := range feed {
		if !domain.PackageIdentityMatch(item.Ecosystem, item.PackageName, component.Ecosystem, queryName) {
			logger.LogIdentityMismatch(purl, component.Ecosystem, component.Name, component.Version, item.PackageName, item.CVEID)
			continue
		}
		if !domain.VersionMatchesEco(component.Ecosystem, item.AffectedVersions, component.Version) {
			logger.LogVersionNoMatch(purl, component.Ecosystem, component.Name, component.Version, item.CVEID)
			continue
		}
		out = append(out, domain.VulnerabilityRecord{
			CVEID:            item.CVEID,
			Severity:         item.Severity,
			CVSSScore:        item.CVSSScore,
			CVSSVector:       item.CVSSVector,
			Ecosystem:        item.Ecosystem,
			PackageName:      item.PackageName,
			AffectedVersions: item.AffectedVersions,
			FixVersions:      item.FixVersions,
			Source:           domain.DefaultFindingSource(item.Source),
		})
	}
	return out, nil
}
