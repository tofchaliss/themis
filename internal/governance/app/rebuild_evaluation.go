package app

import (
	"context"
	"errors"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
)

// The rebuild judgement for one Release (EDR-REBUILD-01 step R2, part 1). It answers, on demand:
// with the policy in force, the tags and the facts on record right now, would a rebuild be asked
// for, and for which components? It is a DRY RUN: it stores nothing, publishes nothing and
// starts nothing. The triggers, the decision record and the two events are part 2.

// ErrRebuildEvaluationUnavailable is returned when the judgement is not wired.
var ErrRebuildEvaluationUnavailable = errors.New("governance: rebuild evaluation not configured")

// RebuildFindingFacts is what the store holds about one Finding that the policy reads.
type RebuildFindingFacts struct {
	FindingID   domain.FindingID
	FaultlineID string
	CVE         string
	Stage       domain.Stage
	// Stance is the Position in force, "" when the Finding is undecided.
	Stance domain.Stance
	// BaseScore is the score priority and the SLA read (0-100), the owner-set one when a person
	// set it; OwnerSet says which.
	BaseScore      int
	OwnerSet       bool
	KnownExploited bool
	// Components are the live (not retired) matched components.
	Components []domain.MatchedComponent
}

// RebuildFactsReader reads those facts for every Finding of one Release, in Finding id order.
type RebuildFactsReader interface {
	RebuildFacts(ctx context.Context, releaseID string) ([]RebuildFindingFacts, error)
}

// ReleaseFixVerdict is Knowledge's recorded answer for one occurrence (D30).
type ReleaseFixVerdict struct {
	FaultlineID string
	PURL        string
	Fix         domain.RebuildFixVerdict
	// FixedVersions are the vendor bounds the occurrence is below; set only with a known fix.
	FixedVersions []string
}

// ReleaseFixVerdictReader reads them from Knowledge, one call per Release.
type ReleaseFixVerdictReader interface {
	ReleaseFixVerdicts(ctx context.Context, releaseID string) ([]ReleaseFixVerdict, error)
}

// Where a targeted entry's severity came from (D34 `score_source`).
const (
	RebuildScoreSourceBase  = "base_score"
	RebuildScoreSourceOwner = "owner_set"
)

// Assessment states of D35. While the calculated component assessment is in shadow
// (EDR-SCORING-01 9.1) the policy reads the same base score priority and the SLA read, so no
// entry is `assessed` yet.
const (
	RebuildAssessmentNotAssessed = "not_assessed"
	RebuildAssessmentNotEligible = "not_eligible"
)

// RebuildFixSourceVerdict is the `fix_source` of an entry in this step: the fix is the one
// Knowledge recorded on the occurrence verdict. Naming the feed is open for part 2.
const RebuildFixSourceVerdict = "knowledge_verdict"

// RebuildEvaluationEntry is one counted component of one Finding with the facts that made it
// count (D34).
type RebuildEvaluationEntry struct {
	domain.RebuildTarget
	CurrentVersion string
	FixedVersions  []string
	// FixSource is "" when no fix is known for the entry (possible only with fix_required off).
	FixSource       string
	Score           int
	ScoreSource     string
	AssessmentState string
}

// RebuildEvaluation is the judgement for one Release.
type RebuildEvaluation struct {
	Policy RebuildPolicyForRelease
	// Outcome is none, recommend or request (domain.RebuildOutcome*).
	Outcome string
	// Considered counts the open component occurrences of open Findings the policy looked at.
	Considered int
	Targeted   []RebuildEvaluationEntry
	// Skipped counts the occurrences that did not count, by reason (domain.RebuildSkipped*).
	Skipped map[string]int
	// FixVerdictsRead is false when Knowledge could not be asked: every fix then reads unknown,
	// and unknown is not a known fix (D30), so nothing counts under fix_required.
	FixVerdictsRead bool
	EvaluatedAt     time.Time
}

// RebuildEvaluationService computes the judgement.
type RebuildEvaluationService struct {
	policy *RebuildPolicyService
	facts  RebuildFactsReader
	fixes  ReleaseFixVerdictReader // nil: every fix reads unknown
	clock  Clock
}

// NewRebuildEvaluationService wires the service. The policy service must have a tag reader:
// without tags there is no effective mode, and Evaluate refuses.
func NewRebuildEvaluationService(policy *RebuildPolicyService, facts RebuildFactsReader, fixes ReleaseFixVerdictReader, clock Clock) *RebuildEvaluationService {
	return &RebuildEvaluationService{policy: policy, facts: facts, fixes: fixes, clock: clock}
}

type occurrenceKey struct{ faultlineID, purl string }

// Evaluate judges one Release now. It fails closed when the policy in force or the tags cannot
// be read. It does NOT fail when Knowledge cannot be asked: the fix verdicts then read unknown,
// which can only make the answer smaller.
func (s *RebuildEvaluationService) Evaluate(ctx context.Context, releaseID string) (RebuildEvaluation, error) {
	if s == nil || s.policy == nil || s.facts == nil {
		return RebuildEvaluation{}, ErrRebuildEvaluationUnavailable
	}
	pol, err := s.policy.InForce(ctx, releaseID)
	if err != nil {
		return RebuildEvaluation{}, err
	}
	if !pol.TagsApplied {
		return RebuildEvaluation{}, ErrRebuildEvaluationUnavailable
	}
	facts, err := s.facts.RebuildFacts(ctx, pol.ReleaseID)
	if err != nil {
		return RebuildEvaluation{}, err
	}
	out := RebuildEvaluation{Policy: pol, EvaluatedAt: s.clock.Now().UTC().Truncate(time.Microsecond)}

	verdicts := map[occurrenceKey]ReleaseFixVerdict{}
	if s.fixes != nil {
		if rows, err := s.fixes.ReleaseFixVerdicts(ctx, pol.ReleaseID); err == nil {
			out.FixVerdictsRead = true
			for _, v := range rows {
				verdicts[occurrenceKey{v.FaultlineID, v.PURL}] = v
			}
		}
	}

	type detail struct {
		version  string
		fixed    []string
		score    int
		ownerSet bool
	}
	var candidates []domain.RebuildCandidate
	details := map[occurrenceKey]detail{}
	for _, f := range facts {
		if f.Stage == domain.StageResolved || f.Stage == domain.StageArchived {
			continue
		}
		for _, c := range f.Components {
			if !c.VerdictIsOpen() {
				continue // the installed build already carries the vendor fix
			}
			fix := domain.RebuildFixUnknown
			var fixed []string
			if v, ok := verdicts[occurrenceKey{f.FaultlineID, c.PURL}]; ok {
				fix, fixed = v.Fix, v.FixedVersions
			}
			candidates = append(candidates, domain.RebuildCandidate{
				FindingID: f.FindingID, CVE: f.CVE, PURL: c.PURL,
				Severity: domain.SLABucketOf(f.BaseScore), KnownExploited: f.KnownExploited,
				Position: f.Stance, ClaimClass: c.ClaimClass, Fix: fix,
			})
			details[occurrenceKey{string(f.FindingID), c.PURL}] = detail{c.Version, fixed, f.BaseScore, f.OwnerSet}
		}
	}
	out.Considered = len(candidates)

	verdict := domain.EvaluateRebuild(pol.InForce.Policy, candidates)
	out.Skipped = verdict.Skipped
	out.Targeted = make([]RebuildEvaluationEntry, 0, len(verdict.Targeted))
	for _, t := range verdict.Targeted {
		d := details[occurrenceKey{string(t.FindingID), t.PURL}]
		e := RebuildEvaluationEntry{
			RebuildTarget: t, CurrentVersion: d.version, Score: d.score,
			ScoreSource: RebuildScoreSourceBase, AssessmentState: RebuildAssessmentNotAssessed,
		}
		if d.ownerSet {
			e.ScoreSource = RebuildScoreSourceOwner
		}
		if t.Fix == domain.RebuildFixKnown {
			e.FixedVersions, e.FixSource = d.fixed, RebuildFixSourceVerdict
		}
		if !(domain.MatchedComponent{ClaimClass: t.ClaimClass}).ActsAsCarrier() {
			e.AssessmentState = RebuildAssessmentNotEligible
		}
		out.Targeted = append(out.Targeted, e)
	}
	out.Outcome = domain.RebuildOutcome(pol.EffectiveMode, len(out.Targeted))
	return out, nil
}
