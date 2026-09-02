package app

import (
	"context"
	"time"
)

// RedHatCVESource fetches one CVE's Red Hat vendor data and returns the source Proposals to
// fold — the vendor-severity vuln-facts Proposal plus any `not_affected` applicability
// statements (EDR-VEX-01 D2 / parity B3). It is per-CVE, so the caller's iteration over the
// already-carded CVEs keeps it relevance-bounded (EDR-KNOWLEDGE-01 D5 — never a full-feed
// mirror). A CVE Red Hat does not track yields no Proposals (nil), not an error.
type RedHatCVESource interface {
	FetchCVE(ctx context.Context, cve string) ([]ProposalFor, error)
}

// RedHatEnrichmentService folds Red Hat vendor data onto EXISTING Faultline cards (D5): it
// iterates the known cards (the bounded set) and fetches each CVE's Red Hat record, folding the
// vendor-severity vuln-facts and any `not_affected` applicability Proposals. Precedence ranks
// `redhat` distro-authoritative, so its statements headline the reconciled distro view; the
// applicability rides the Phase-2 suppression overlay in Governance. It covers RHEL and its 1:1
// rebuilds (Rocky, Alma) because the vendor verdict keys on the RPM package, not the distro
// label. Idempotent — re-folding a Red Hat Proposal converges.
type RedHatEnrichmentService struct {
	source RedHatCVESource
	known  KnownCVEs
	fold   *FaultlineService

	// The D10 change gate — an EFFICIENCY gate that must never become a correctness gate.
	// signal==nil (or a signal failure) means every sweep is full, exactly the pre-D10
	// behavior. fetched and lastSweep are deliberately in-memory only: a restart forgets
	// them, forcing one full sweep, which is what heals any change signal this process
	// missed while it was down.
	signal    RedHatChangeSignal
	clock     Clock
	fetched   map[string]struct{}
	lastSweep time.Time
}

// RedHatChangeSignal supplies the modified-since change signal for the D10 sweep gate: the
// set of canonical CVE ids whose Red Hat security data changed since t. ok=false means the
// signal is unavailable this sweep (fetch or parse failure) — the caller then falls back to
// a full sweep, so a broken signal can only cost requests, never freshness.
type RedHatChangeSignal interface {
	ChangedSince(ctx context.Context, since time.Time) (changed map[string]struct{}, ok bool)
}

// NewRedHatEnrichmentService wires the enrichment ports.
func NewRedHatEnrichmentService(source RedHatCVESource, known KnownCVEs, fold *FaultlineService) *RedHatEnrichmentService {
	return &RedHatEnrichmentService{source: source, known: known, fold: fold, fetched: map[string]struct{}{}}
}

// WithChangeSignal arms the D10 change gate: subsequent sweeps fetch per-CVE only what the
// signal reports changed since the last completed sweep, or what this process never fetched.
// The first sweep stays full (nothing is fetched yet), and the clock stamps the watermark.
func (s *RedHatEnrichmentService) WithChangeSignal(signal RedHatChangeSignal, clock Clock) *RedHatEnrichmentService {
	s.signal = signal
	s.clock = clock
	return s
}

// Enrich runs one Red Hat enrichment sweep and returns how many Proposals were folded. It
// iterates the known cards and fetches each CVE's Red Hat data; a per-CVE fetch error is
// skipped (a CVE Red Hat does not track is normal, and a transient fetch error is retried next
// sweep), so one gap never aborts the whole sweep. A fold (store) error IS fatal to the sweep —
// it signals a real persistence fault, not a feed gap; the watermark does not advance on it, so
// the next sweep re-reads a superset of the change window.
//
// With the D10 gate armed, a sweep skips a CVE only when BOTH hold: this process already
// fetched it once, AND the signal says it has not changed since the last completed sweep. A
// successful nil answer ("Red Hat does not track this CVE") counts as fetched — that answer is
// stable, and the change signal is what re-triggers it if Red Hat starts tracking it later.
func (s *RedHatEnrichmentService) Enrich(ctx context.Context) (int, error) {
	known, err := s.known.KnownCVEs(ctx)
	if err != nil {
		return 0, err
	}
	if len(known) == 0 {
		return 0, nil // nothing carded yet — no relevant CVE to enrich
	}
	var sweepStart time.Time
	if s.clock != nil {
		sweepStart = s.clock.Now()
	}
	var changed map[string]struct{}
	gated := false
	if s.signal != nil && !s.lastSweep.IsZero() {
		changed, gated = s.signal.ChangedSince(ctx, s.lastSweep)
	}
	folded := 0
	for cve := range known {
		if gated {
			_, seen := s.fetched[cve]
			_, isChanged := changed[cve]
			if seen && !isChanged {
				continue // fetched before and unchanged since the last completed sweep
			}
		}
		props, err := s.source.FetchCVE(ctx, cve)
		if err != nil {
			continue // no Red Hat data for this CVE, or a transient fetch error — skip it
		}
		s.fetched[cve] = struct{}{}
		for _, p := range props {
			if _, _, ferr := s.fold.FoldProposal(ctx, p.CVE, p.Proposal); ferr != nil {
				return folded, ferr
			}
			folded++
		}
	}
	s.lastSweep = sweepStart
	return folded, nil
}
