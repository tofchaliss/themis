package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// EvidencePresenceReader reads whether any evidence is filed against a release, from
// Evidence's read API over a small client seam (EDR-GOVERNANCE-01 D16) — like the
// Registry blast-radius and Knowledge assessment seams, Governance never imports the
// Evidence context.
type EvidencePresenceReader interface {
	HasEvidence(ctx context.Context, releaseID string) (bool, error)
}

// ReleaseComparison is the cross-release posture diff (D16): what a candidate build fixed,
// introduced, and failed to cover, relative to a baseline. Fixed rows carry the BASELINE's
// state — a fix closes the question forward, it never rewrites the baseline's record —
// while New and Persisting carry the CANDIDATE's. Each bucket is sorted by residual then
// effective priority, descending: the server owns the ordering, so every consumer (GUI,
// AI, report) reads the same answer.
type ReleaseComparison struct {
	BaselineReleaseID  string
	CandidateReleaseID string
	Fixed              []PostureEntry
	New                []PostureEntry
	Persisting         []PostureEntry
}

// NoEvidenceError names the release(s) a comparison refused to diff against (D16): "fixed"
// is absence proven by NEW evidence, and a release with no evidence has proven nothing —
// diffing against it would read every baseline CVE as fixed.
type NoEvidenceError struct {
	ReleaseIDs []string
}

func (e *NoEvidenceError) Error() string {
	return "no evidence filed against release(s) " + strings.Join(e.ReleaseIDs, ", ") +
		" — absence of a Finding there proves nothing; upload the release's SBOM first"
}

// ErrEvidenceUnavailable marks a comparison refused because Evidence could not be asked
// whether a release has evidence. Deliberately fail-CLOSED — the opposite of the
// blast-radius 1.0 fail-safe, because degrading silently here would over-claim "fixed".
var ErrEvidenceUnavailable = errors.New("evidence unavailable: cannot verify release evidence, refusing to compare")

// WithEvidence wires the Evidence presence seam the compare read requires (D16) and returns
// the service for chaining. Left nil, CompareReleases refuses (fail-closed) while every
// other read is unaffected.
func (s *ReadService) WithEvidence(e EvidencePresenceReader) *ReadService {
	s.evidence = e
	return s
}

// CompareReleases diffs two releases' postures by CVE (D16): fixed = a baseline Finding's
// CVE opens no Finding on the candidate, new = candidate-only, persisting = both. Each side's
// posture keeps its own blast multiplier — the diff is over the same rows a posture read
// returns, computed once, here, for every consumer.
func (s *ReadService) CompareReleases(ctx context.Context, baselineID, candidateID string) (ReleaseComparison, error) {
	if s.evidence == nil {
		return ReleaseComparison{}, ErrEvidenceUnavailable
	}
	var missing []string
	for _, id := range []string{baselineID, candidateID} {
		has, err := s.evidence.HasEvidence(ctx, id)
		if err != nil {
			return ReleaseComparison{}, fmt.Errorf("%w: %v", ErrEvidenceUnavailable, err)
		}
		if !has {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		return ReleaseComparison{}, &NoEvidenceError{ReleaseIDs: missing}
	}

	baseline, err := s.ReleasePosture(ctx, baselineID)
	if err != nil {
		return ReleaseComparison{}, err
	}
	candidate, err := s.ReleasePosture(ctx, candidateID)
	if err != nil {
		return ReleaseComparison{}, err
	}

	inCandidate := make(map[string]bool, len(candidate))
	for _, p := range candidate {
		inCandidate[p.CVE] = true
	}
	inBaseline := make(map[string]bool, len(baseline))
	for _, p := range baseline {
		inBaseline[p.CVE] = true
	}

	out := ReleaseComparison{BaselineReleaseID: baselineID, CandidateReleaseID: candidateID}
	for _, p := range baseline {
		if !inCandidate[p.CVE] {
			out.Fixed = append(out.Fixed, p)
		}
	}
	for _, p := range candidate {
		if inBaseline[p.CVE] {
			out.Persisting = append(out.Persisting, p)
		} else {
			out.New = append(out.New, p)
		}
	}
	for _, bucket := range [][]PostureEntry{out.Fixed, out.New, out.Persisting} {
		sort.SliceStable(bucket, func(i, j int) bool {
			if bucket[i].ResidualPriority != bucket[j].ResidualPriority {
				return bucket[i].ResidualPriority > bucket[j].ResidualPriority
			}
			return bucket[i].EffectivePriority > bucket[j].EffectivePriority
		})
	}
	return out, nil
}
