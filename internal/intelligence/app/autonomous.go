package app

// The Δ4b autonomous plane, walking skeleton (EDR-INTELLIGENCE-01 § Δ4b): ONE analyst
// (cross-release decision-consistency) on a cadence, spending from a SEPARATE capped pool with
// pause-not-fail, pushing advisory proposals through the existing Governance seam. Generation
// with no caller — but never authority: every push is an advisory `ai` proposal Governance can
// never auto-accept (the group-1 tripwire).

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

// ReleaseLister enumerates the releases the analyst sweeps — Registry's estate, over the
// existing read-API client seam (the analyst composes existing reads; it needs no new endpoint).
type ReleaseLister interface {
	ListReleaseIDs(ctx context.Context) ([]string, error)
}

// ProposedRecorder is the idempotence record (Δ4b D-Δ4b-5): skip already-proposed (finding,
// precedent) pairs; re-propose only when the precedent key changes.
type ProposedRecorder interface {
	HasProposed(ctx context.Context, findingID, precedentKey string) (bool, error)
	RecordProposed(ctx context.Context, findingID, precedentKey string) error
}

// AutonomousSweep runs the cross-release-consistency analyst once per invocation (D-Δ4b-2/3/4).
// It is disabled unless an autonomous pool is configured — the pool's existence is the enable
// switch (D-Δ4b-4), so a node with no pool never sweeps.
type AutonomousSweep struct {
	releases  ReleaseLister
	posture   ProjectionReader
	precedent *PrecedentService
	raiser    ProposalRaiser
	recorder  ProposedRecorder
	pool      *Budget // the SEPARATE autonomous pool; nil/disabled ⇒ the sweep is off
	now       func() time.Time
	// AUTO-VOL-1 volume controls (measured live 2026-08-26: one decision cascaded to 110
	// proposals in a single sweep). The guardrails contain the danger; these contain the noise.
	minScore   float64 // minimum cosine similarity a precedent must clear to be advised on
	minOverlap float64 // minimum release-overlap (G-AI-3 delta) a precedent must clear
	maxPerPass int     // hard cap on proposals pushed in one sweep (0 = uncapped)
}

// Default volume controls (AUTO-VOL-1). Chosen so a WEAK match (a different CVE that merely
// shares a component, or a precedent from a barely-overlapping release) no longer triggers an
// advisory — only a strong, clearly-relevant precedent does. A first-run sweep also caps its
// output so one enable can never firehose the triage board.
const (
	defaultMinPrecedentScore = 0.75 // strong cosine; below this the neighbour is "vaguely similar", not precedent
	defaultMinReleaseOverlap = 0.5  // the two releases share at least half their open surface
	// DefaultAutoMaxPerPass is the per-sweep proposal cap the composition root falls back to when
	// the operator sets other volume knobs but leaves the cap unset (AUTO-VOL-1).
	DefaultAutoMaxPerPass = 20
)

// NewAutonomousSweep wires the analyst. A nil or disabled pool disables the sweep entirely.
// The volume controls default to the constants above; override with WithVolumeControls.
func NewAutonomousSweep(
	releases ReleaseLister, posture ProjectionReader, precedent *PrecedentService,
	raiser ProposalRaiser, recorder ProposedRecorder, pool *Budget,
) *AutonomousSweep {
	return &AutonomousSweep{
		releases: releases, posture: posture, precedent: precedent,
		raiser: raiser, recorder: recorder, pool: pool, now: time.Now,
		minScore: defaultMinPrecedentScore, minOverlap: defaultMinReleaseOverlap,
		maxPerPass: DefaultAutoMaxPerPass,
	}
}

// WithClock overrides the clock (tests).
func (s *AutonomousSweep) WithClock(now func() time.Time) *AutonomousSweep {
	s.now = now
	return s
}

// WithVolumeControls overrides the AUTO-VOL-1 gate + cap (config-driven from the composition
// root). A non-positive minScore/minOverlap keeps its default; a non-positive maxPerPass means
// UNCAPPED (an operator who deliberately wants no cap). Returns the sweep for chaining.
func (s *AutonomousSweep) WithVolumeControls(minScore, minOverlap float64, maxPerPass int) *AutonomousSweep {
	if minScore > 0 {
		s.minScore = minScore
	}
	if minOverlap > 0 {
		s.minOverlap = minOverlap
	}
	s.maxPerPass = maxPerPass // 0/negative = uncapped, an explicit operator choice
	return s
}

// Enabled reports whether the sweep will do anything (the pool is the switch).
func (s *AutonomousSweep) Enabled() bool { return s.pool != nil && s.pool.Enabled() }

// SweepResult is the outcome of one pass — provenance for the operator/telemetry.
type SweepResult struct {
	Proposed int  // advisory proposals pushed this pass
	Skipped  int  // undecided Findings skipped (no precedent, or already proposed)
	Examined int  // undecided Findings looked at
	Paused   bool // the pool drained mid-pass (drain-then-stop)
	Capped   bool // the per-pass proposal cap was hit — the rest waits for the next window (AUTO-VOL-1)
	PushErrs int  // per-Finding push failures (non-fatal)
}

// candidate is one undecided Finding worth a proposal, with its grounding precedent.
type candidate struct {
	findingID    string
	releaseID    string
	stance       string // the precedent's decided stance — what we advise
	rationale    string
	precedentKey string
	priority     int
}

// Run performs one sweep: gather undecided Findings across releases that have a decided
// precedent on a similar release, worst-first, pushing an advisory proposal for each and
// debiting the pool — pausing (drain-then-stop) when the pool cannot admit the next push.
func (s *AutonomousSweep) Run(ctx context.Context) (SweepResult, error) {
	var res SweepResult
	if !s.Enabled() {
		return res, nil
	}
	cands, err := s.gather(ctx, &res)
	if err != nil {
		return res, err
	}
	// Worst-first (D-Δ4b-4): the residual priority already on the posture row, no new value model.
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].priority > cands[j].priority })

	for _, c := range cands {
		// The per-pass cap (AUTO-VOL-1): even under budget, one sweep never pushes more than
		// maxPerPass proposals — the remainder waits for the next window, worst-first. Stops one
		// enable firehosing the triage board (measured: 110 in a single sweep). The
		// idempotence record keeps a capped candidate available (unproposed) next pass.
		if s.maxPerPass > 0 && res.Proposed >= s.maxPerPass {
			res.Capped = true
			break
		}
		// The pool is the wall: when it cannot admit the next push, stop here and resume next
		// window (drain-then-stop). One proposal ~ one unit; the pool is token-denominated, so a
		// nominal debit per push keeps the skeleton simple while honoring the envelope.
		if !s.pool.Allow(s.now()) {
			res.Paused = true
			break
		}
		already, herr := s.recorder.HasProposed(ctx, c.findingID, c.precedentKey)
		if herr == nil && already {
			res.Skipped++
			continue
		}
		if perr := s.raiser.RaiseAIProposal(ctx, c.findingID, c.stance, c.rationale); perr != nil {
			res.PushErrs++ // per-Finding failure, never fatal to the sweep
			continue
		}
		s.pool.Debit(s.now(), autonomousProposalCost)
		_ = s.recorder.RecordProposed(ctx, c.findingID, c.precedentKey)
		res.Proposed++
	}
	return res, nil
}

// autonomousProposalCost is the nominal per-push debit against the pool. The skeleton meters
// PUSHES rather than model tokens (the analyst's grounding reuses cheap reads + one precedent
// lookup, no generation), so a token-denominated pool with a flat per-proposal cost bounds the
// pass without a second cost model. A later refinement can debit actual tokens if the analyst
// grows a generative step.
const autonomousProposalCost = 1

func (s *AutonomousSweep) gather(ctx context.Context, res *SweepResult) ([]candidate, error) {
	releaseIDs, err := s.releases.ListReleaseIDs(ctx)
	if err != nil {
		return nil, err
	}
	var cands []candidate
	for _, relID := range releaseIDs {
		posture, perr := s.posture.GetReleasePosture(ctx, relID)
		if perr != nil {
			continue // one unreadable release must not stop the sweep
		}
		for _, e := range posture.Entries {
			if e.Stance != "" {
				continue // decided — not our concern (the disposition-watcher owns suppressed ones)
			}
			res.Examined++
			// Precedent for THIS undecided Finding: a decided Position on a similar release.
			precs := s.precedent.Retrieve(ctx, PrecedentQuery{
				Severity: severityOf(e), Components: componentsOf(e),
				FaultlineID: "", ReleaseID: relID,
			})
			best, ok := s.bestQualifyingPrecedent(precs)
			if !ok {
				res.Skipped++ // no precedent, or none STRONG enough to advise on (AUTO-VOL-1)
				continue
			}
			cands = append(cands, candidate{
				findingID: e.FindingID, releaseID: relID,
				stance:       best.Stance,
				rationale:    fmt.Sprintf("Consistency: CVE %s was decided %q on release %s (a similar release). Consider the same here.", best.SourceCVE, best.Stance, best.ReleaseID),
				precedentKey: precedentKey(best),
				priority:     e.ResidualPriority,
			})
		}
	}
	return cands, nil
}

// bestQualifyingPrecedent returns the highest-ranked precedent that is DECIDED and STRONG enough
// to advise on (AUTO-VOL-1): a cosine score at/above minScore, and — when the delta overlap is
// known — a release overlap at/above minOverlap. Precedents arrive delta-ranked (G-AI-3), so the
// first qualifier is the best. This is what stops one accepted decision cascading into a proposal
// on every vaguely-similar undecided Finding across the estate.
//
// An exact-CVE fallback precedent has Score 0 by construction (matched by lookup, not similarity)
// but is by definition the SAME CVE — maximally relevant — so it qualifies on identity, exempt
// from the score floor. Unknown overlap does not disqualify (an unreadable comparison must not
// silence a strong same-CVE precedent), but a KNOWN-and-low overlap does.
func (s *AutonomousSweep) bestQualifyingPrecedent(precs []domain.PrecedentPosition) (domain.PrecedentPosition, bool) {
	for _, p := range precs {
		if p.Stance == "" {
			continue // undecided precedent is not precedent
		}
		exactCVE := p.Score == 0 // the Δ2 exact-CVE fallback — same CVE, exempt from the cosine floor
		if !exactCVE && p.Score < s.minScore {
			continue
		}
		if p.OverlapKnown && p.ReleaseOverlap < s.minOverlap {
			continue
		}
		return p, true
	}
	return domain.PrecedentPosition{}, false
}

// precedentKey encodes the precedent's identity so a CHANGED precedent (different release,
// stance, or source CVE) re-proposes (D-Δ4b-5). Deterministic and stable.
func precedentKey(p domain.PrecedentPosition) string {
	return p.ReleaseID + "|" + p.SourceCVE + "|" + p.Stance
}

// severityOf / componentsOf pull the precedent query inputs from a posture entry. The posture
// row carries neither a severity nor purls directly for the skeleton, so severity is left empty
// (the precedent search still works on components); components map from the entry's own list.
func severityOf(domain.PostureEntry) string { return "" }

func componentsOf(e domain.PostureEntry) []string {
	out := make([]string, 0, len(e.Components))
	for _, c := range e.Components {
		if c.PURL != "" {
			out = append(out, c.PURL)
		}
	}
	return out
}
