package osv

import (
	"context"

	"github.com/themis-project/themis/internal/domain"
)

// ComponentFetcher queries OSV when the local vulnerability cache has no matches.
type ComponentFetcher struct {
	Client *Client
}

// FetchForComponent returns CVE records affecting the component from OSV.
func (f ComponentFetcher) FetchForComponent(ctx context.Context, component domain.CanonicalComponent) ([]domain.VulnerabilityRecord, error) {
	if f.Client == nil || component.Name == "" {
		return nil, nil
	}
	if _, ok := MapEcosystem(component.Ecosystem); !ok {
		return nil, nil
	}
	feed, err := f.Client.QueryByEcosystem(ctx, component.Ecosystem, []domain.OSVPackageQuery{{Name: component.Name}})
	if err != nil {
		return nil, err
	}
	var out []domain.VulnerabilityRecord
	for _, item := range feed {
		if !domain.PackageIdentityMatch(item.Ecosystem, item.PackageName, component.Ecosystem, component.Name) {
			continue
		}
		if !domain.VersionMatches(item.AffectedVersions, component.Version) {
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
		})
	}
	return out, nil
}
