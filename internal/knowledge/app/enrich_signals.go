package app

import (
	"context"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// ExploitSignalSource is the bulk exploit-signal snapshot port (D5 enrichment): the full
// per-CVE EPSS / KEV / public-exploit signal keyed by canonical CVE string. Unlike the
// modified-since watch, exploit feeds publish a full snapshot each cycle, so the source
// returns the whole map and the enrichment sweep applies only the already-carded entries.
type ExploitSignalSource interface {
	Signals(ctx context.Context) (map[string]domain.ExploitSignal, error)
}

// SignalEnrichmentService folds exploit signals (EPSS / KEV / public-exploit) onto EXISTING
// Faultline cards (EDR-KNOWLEDGE-01 D5 — bounded by relevance, never a full feed mirror). It
// loads the known-CVE set and the signal snapshot and folds a signal Proposal only for CVEs
// that already have a card, so the fold find-and-enriches (never creates). It is idempotent —
// re-folding a signal converges (KEV / public-exploit OR, EPSS latest-wins).
type SignalEnrichmentService struct {
	signals ExploitSignalSource
	known   KnownCVEs
	fold    *FaultlineService
	clock   Clock
}

// NewSignalEnrichmentService wires the enrichment ports.
func NewSignalEnrichmentService(signals ExploitSignalSource, known KnownCVEs, fold *FaultlineService, clock Clock) *SignalEnrichmentService {
	return &SignalEnrichmentService{signals: signals, known: known, fold: fold, clock: clock}
}

// signalSource stamps the source name on every exploit-signal Proposal the sweep folds.
const signalSource = "epsskev"

// Enrich runs one enrichment sweep and returns how many cards were folded. It iterates the
// known cards (the smaller set) and looks each up in the snapshot, so a full EPSS feed of
// hundreds of thousands of CVEs never widens the card population. Safe to run on any cadence
// and safe to re-run.
func (s *SignalEnrichmentService) Enrich(ctx context.Context) (int, error) {
	known, err := s.known.KnownCVEs(ctx)
	if err != nil {
		return 0, err
	}
	if len(known) == 0 {
		return 0, nil // nothing carded yet — no relevant CVE to enrich
	}
	signals, err := s.signals.Signals(ctx)
	if err != nil {
		return 0, err
	}
	now := s.clock.Now()
	folded := 0
	for cve := range known {
		sig, ok := signals[cve]
		if !ok {
			continue // this card has no exploit signal this cycle
		}
		cveID, err := value.NewCVEID(cve)
		if err != nil {
			continue // a carded CVE that no longer parses — skip defensively
		}
		p, err := domain.NewExploitSignalProposal(signalSource, now, sig)
		if err != nil {
			continue // one malformed signal (e.g. EPSS out of range) — keep sweeping
		}
		if _, err := s.fold.FoldProposal(ctx, cveID, p); err != nil {
			return folded, err
		}
		folded++
	}
	return folded, nil
}
