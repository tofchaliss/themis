package app

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// InventoryComponent is one component of a release's canonical inventory, read from
// Evidence via its read API (never Evidence's tables — Book III §3.5).
type InventoryComponent struct {
	PURL      string
	Name      string
	Version   string
	Ecosystem string
}

// Inventory is the subset of Evidence's canonical inventory correlation needs.
type Inventory struct {
	Components []InventoryComponent
}

// InventoryReader reads a release's inventory from Evidence's read API (D4). Knowledge
// keeps no copy — reads are transient, per correlation run.
type InventoryReader interface {
	GetInventory(ctx context.Context, evidenceID string) (Inventory, error)
}

// ProposalFor is a discovered source Proposal bound to a canonical CVE.
type ProposalFor struct {
	CVE      value.CVEID
	Proposal domain.Proposal
}

// PackageVulnSource is the lazy-discovery port (D5): given a component, it returns the
// source Proposals for the CVEs that affect that package (e.g. an OSV query-by-package
// client). Card population stays bounded by components the enterprise has actually seen.
type PackageVulnSource interface {
	VulnsForPackage(ctx context.Context, component InventoryComponent) ([]ProposalFor, error)
}

// Match is a release component that matched a Faultline.
type Match struct {
	ReleaseID   string
	FaultlineID domain.FaultlineID
	CVE         string
	Component   InventoryComponent
	OccurredAt  time.Time
}

// MatchRecorder records matches idempotently and queues the ComponentMatched event; it
// also advances the matched card to the Correlated stage (D3/D7). It returns whether the
// match was new so a re-scan of the same occurrence emits no duplicate.
type MatchRecorder interface {
	RecordMatch(ctx context.Context, m Match) (bool, error)
}

// CorrelationService owns correlation (D3): it reads a release's inventory, discovers
// the vulnerabilities affecting each component, folds those source Proposals into the
// enterprise cards, and records a match per (release, faultline, component) — emitting
// ComponentMatched for Governance to open a Finding (EDR-GOVERNANCE-01 D5).
type CorrelationService struct {
	inventory InventoryReader
	discover  PackageVulnSource
	fold      *FaultlineService
	matches   MatchRecorder
	clock     Clock
}

// NewCorrelationService wires the correlation ports.
func NewCorrelationService(inv InventoryReader, disc PackageVulnSource, fold *FaultlineService, matches MatchRecorder, clock Clock) *CorrelationService {
	return &CorrelationService{inventory: inv, discover: disc, fold: fold, matches: matches, clock: clock}
}

// Correlate runs correlation for one registered SBOM: read the inventory, discover and
// fold per-component vulnerabilities, and record matches. It is idempotent — a re-run
// re-folds Proposals (which converge) and records no duplicate matches. It returns the
// number of new matches.
func (s *CorrelationService) Correlate(ctx context.Context, releaseID, evidenceID string) (int, error) {
	inv, err := s.inventory.GetInventory(ctx, evidenceID)
	if err != nil {
		return 0, err
	}

	newMatches := 0
	for _, comp := range inv.Components {
		discovered, err := s.discover.VulnsForPackage(ctx, comp)
		if err != nil {
			return newMatches, err
		}
		for _, d := range discovered {
			faultlineID, err := s.fold.FoldProposal(ctx, d.CVE, d.Proposal)
			if err != nil {
				return newMatches, err
			}
			created, err := s.matches.RecordMatch(ctx, Match{
				ReleaseID: releaseID, FaultlineID: faultlineID, CVE: d.CVE.String(),
				Component: comp, OccurredAt: s.clock.Now(),
			})
			if err != nil {
				return newMatches, err
			}
			if created {
				newMatches++
			}
		}
	}
	return newMatches, nil
}
