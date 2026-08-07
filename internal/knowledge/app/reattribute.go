package app

import (
	"context"

	"github.com/themis-project/themis/internal/kernel/value"
)

// UnattributedCard is a card whose fix versions carry no package, together with one component
// that matched it — enough to ask the feeds about it again.
type UnattributedCard struct {
	CVE       string
	Component InventoryComponent
}

// UnattributedCardReader finds cards holding fix versions that no package is attributed to.
type UnattributedCardReader interface {
	// CardsNeedingAttribution returns up to limit cards whose reconciled view holds at least one
	// fix version with an empty package, paired with a component known to have matched them.
	CardsNeedingAttribution(ctx context.Context, limit int) ([]UnattributedCard, error)
}

// ReattributeService re-asks the feeds about components already in the estate, so cards folded
// before fix-attribution existed gain it without waiting for a new SBOM (KN-FIX-2).
//
// Why a sweep is needed at all: only OSV and Red Hat attribute a fix to a package — NVD keys on
// CPE and scanners report bare versions, both correctly recording unattributed fixes. OSV is
// queried during CORRELATION, which runs on UPLOAD. So a card whose releases are not re-uploaded
// keeps its flat pre-attribution list indefinitely, while the per-CVE NVD backfill keeps
// appending more unattributed fixes to it — the ratio gets worse, not better. And because
// Evidence is content-addressed, re-uploading identical bytes DEDUPS, so "upload it again" is not
// a workaround an operator can actually use.
//
// It is deliberately built on the same shape as BackfillService: bounded per run, per-record
// failures skipped rather than fatal, and idempotent — folding is append-only and the aggregate
// now drops verbatim restatements (KN-PROPOSAL-BLOAT-1), so a sweep that finds nothing new writes
// nothing at all. Re-running it is free.
type ReattributeService struct {
	reader   UnattributedCardReader
	discover ComponentVulnSource
	fold     *FaultlineService
	limit    int
}

// ComponentVulnSource is the per-component discovery seam correlation already uses; the sweep
// re-uses it rather than inventing a second path to the same feeds.
type ComponentVulnSource interface {
	VulnsForPackage(ctx context.Context, component InventoryComponent) ([]ProposalFor, error)
}

// DefaultReattributeLimit caps one sweep, so a large estate drains over successive runs instead
// of one run issuing thousands of feed requests.
const DefaultReattributeLimit = 100

// NewReattributeService wires the sweep. A limit <= 0 falls back to the default.
func NewReattributeService(
	reader UnattributedCardReader, discover ComponentVulnSource, fold *FaultlineService, limit int,
) *ReattributeService {
	if limit <= 0 {
		limit = DefaultReattributeLimit
	}
	return &ReattributeService{reader: reader, discover: discover, fold: fold, limit: limit}
}

// Sweep runs one pass and returns how many cards were re-folded with attributed fixes.
//
// A per-card failure is skipped, not fatal: one unreachable feed or one unparseable record must
// not stall the rest, and the card simply stays in the queue for the next run. Only the queue
// read aborts, because without it there is no work to do.
func (s *ReattributeService) Sweep(ctx context.Context) (int, error) {
	cards, err := s.reader.CardsNeedingAttribution(ctx, s.limit)
	if err != nil {
		return 0, err
	}
	folded := 0
	for _, c := range cards {
		discovered, derr := s.discover.VulnsForPackage(ctx, c.Component)
		if derr != nil {
			continue
		}
		for _, pf := range discovered {
			// Only fold back what concerns THIS card. A component query returns every CVE
			// affecting the package, and folding all of them here would turn a re-attribution
			// sweep into an undeclared discovery pass — same writes, but no longer the operation
			// the operator asked for or the one this service is bounded for.
			if !sameCVE(pf.CVE, c.CVE) {
				continue
			}
			_, recorded, ferr := s.fold.FoldProposal(ctx, pf.CVE, pf.Proposal)
			if ferr != nil {
				continue
			}
			// A re-run over already-attributed cards records nothing, and must report zero —
			// that is precisely the signal that the sweep has finished its work.
			if recorded {
				folded++
			}
		}
	}
	return folded, nil
}

func sameCVE(a value.CVEID, b string) bool { return a.String() == b }
