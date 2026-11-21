package app

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
)

// Per-component CVSS assessment in shadow (EDR-SCORING-01 S4). Every current component of a
// Finding gets an immutable ComponentAssessment revision with its complete candidate snapshot,
// and the Finding gets a roll-up revision. Nothing here reads or changes priority, SLA, stage or
// Position (EDR 8.6): the results are only served by GET /findings/{id}/score.

// SourceRatingsReader reads a Faultline's source ratings from Knowledge's read API, mapped into
// selection candidates.
type SourceRatingsReader interface {
	SourceRatings(ctx context.Context, faultlineID string) ([]domain.ScoreCandidate, error)
}

// RequirementsReader reads a Release's resolved CR / IR / AR from Registry's read API.
type RequirementsReader interface {
	ResolvedRequirements(ctx context.Context, releaseID string) (domain.ScoreRequirements, error)
}

// ScoreRevision is one immutable ComponentAssessment revision.
type ScoreRevision struct {
	FindingID   string
	PURL        string
	Revision    int
	Cause       string
	Fingerprint string
	Snapshot    domain.ComponentScore
	RecordedAt  time.Time
}

// RollupRevision is one immutable Finding roll-up revision.
type RollupRevision struct {
	FindingID   string
	Revision    int
	Cause       string
	Fingerprint string
	Snapshot    domain.FindingScore
	RecordedAt  time.Time
}

// ScoreRevisionSummary is one past revision, for the history list.
type ScoreRevisionSummary struct {
	PURL       string
	Revision   int
	Cause      string
	Status     string
	Score      *float64
	RecordedAt time.Time
}

// ScoreStore keeps the revisions. AppendScores writes the given revisions in one transaction,
// numbering each after the current one; the store never updates a revision.
type ScoreStore interface {
	CurrentScores(ctx context.Context, findingID string) ([]ScoreRevision, *RollupRevision, error)
	AppendScores(ctx context.Context, findingID string, comps []ScoreRevision, rollup *RollupRevision) error
	ScoreHistory(ctx context.Context, findingID string) ([]ScoreRevisionSummary, error)
	// FindingIDsAfter pages every Finding id in id order, for the re-assessment sweep.
	FindingIDsAfter(ctx context.Context, after string, limit int) ([]string, error)
}

// FindingLoader loads one Finding.
type FindingLoader interface {
	GetByID(ctx context.Context, id domain.FindingID) (domain.Finding, error)
}

// ErrScoreUnavailable is returned when the score read seam is not wired.
var ErrScoreUnavailable = errors.New("governance: score assessment not configured")

// ScoreService assesses Findings and serves the stored result.
type ScoreService struct {
	findings  FindingLoader
	knowledge FaultlineKnowledgeReader
	ratings   SourceRatingsReader
	reqs      RequirementsReader
	store     ScoreStore
	clock     Clock
}

// NewScoreService builds the service. reqs may be nil (no Registry seam): every requirement is
// then X at level default, which is what an unset requirement means anyway.
func NewScoreService(findings FindingLoader, kn FaultlineKnowledgeReader, ratings SourceRatingsReader, reqs RequirementsReader, store ScoreStore, clock Clock) *ScoreService {
	return &ScoreService{findings: findings, knowledge: kn, ratings: ratings, reqs: reqs, store: store, clock: clock}
}

// scoreCache holds the reads one sweep shares: many Findings rest on one card or one release.
type scoreCache struct {
	ratings   map[string][]domain.ScoreCandidate
	knowledge map[string]FaultlineKnowledge
	reqs      map[string]domain.ScoreRequirements
}

func newScoreCache() *scoreCache {
	return &scoreCache{ratings: map[string][]domain.ScoreCandidate{}, knowledge: map[string]FaultlineKnowledge{}, reqs: map[string]domain.ScoreRequirements{}}
}

// Assess re-assesses one Finding and writes a revision only for what changed. It reports
// whether anything was written. A failed read writes nothing: an assessment is never built
// from partial inputs.
func (s *ScoreService) Assess(ctx context.Context, id domain.FindingID) (bool, error) {
	return s.assess(ctx, id, newScoreCache())
}

func (s *ScoreService) assess(ctx context.Context, id domain.FindingID, cache *scoreCache) (bool, error) {
	f, err := s.findings.GetByID(ctx, id)
	if err != nil {
		return false, err
	}
	in, k, err := s.inputs(ctx, f, cache)
	if err != nil {
		return false, err
	}
	current, rollup, err := s.store.CurrentScores(ctx, string(id))
	if err != nil {
		return false, err
	}
	byPURL := map[string]*ScoreRevision{}
	for i := range current {
		byPURL[current[i].PURL] = &current[i]
	}
	now := s.clock.Now().UTC()
	var writes []ScoreRevision
	var causes []string
	scores := make([]domain.ComponentScore, 0, len(f.ActiveComponents()))
	active := map[string]bool{}
	for _, c := range f.ActiveComponents() {
		next := domain.SelectComponentScore(scoreComponent(c, k), in)
		scores = append(scores, next)
		active[c.PURL] = true
		fp := domain.ContentFingerprint(next)
		prev := byPURL[c.PURL]
		if prev != nil && prev.Fingerprint == fp {
			continue
		}
		var prevSnap *domain.ComponentScore
		if prev != nil {
			prevSnap = &prev.Snapshot
		}
		cause := domain.ScoreCause(prevSnap, next)
		causes = append(causes, cause)
		writes = append(writes, ScoreRevision{FindingID: string(id), PURL: c.PURL, Cause: cause, Fingerprint: fp, Snapshot: next, RecordedAt: now})
	}
	roll := domain.RollUp(scores)
	rfp := domain.ContentFingerprint(roll)
	var rollWrite *RollupRevision
	if rollup == nil || rollup.Fingerprint != rfp {
		removed := false
		if rollup != nil {
			for _, p := range rollup.Snapshot.Contributors {
				if !active[p] {
					removed = true
				}
			}
			for _, u := range rollup.Snapshot.Unassessed {
				if !active[u.PURL] {
					removed = true
				}
			}
		}
		rollWrite = &RollupRevision{FindingID: string(id), Cause: domain.RollupCause(removed, causes), Fingerprint: rfp, Snapshot: roll, RecordedAt: now}
	}
	if len(writes) == 0 && rollWrite == nil {
		return false, nil
	}
	return true, s.store.AppendScores(ctx, string(id), writes, rollWrite)
}

// inputs gathers the selection input for a Finding: its card's source ratings, the release's
// requirements and the card's KEV listing and fixes.
func (s *ScoreService) inputs(ctx context.Context, f domain.Finding, cache *scoreCache) (domain.ScoreInput, FaultlineKnowledge, error) {
	fl := f.FaultlineID()
	cands, ok := cache.ratings[fl]
	if !ok {
		var err error
		if cands, err = s.ratings.SourceRatings(ctx, fl); err != nil {
			return domain.ScoreInput{}, FaultlineKnowledge{}, err
		}
		cache.ratings[fl] = cands
	}
	k, ok := cache.knowledge[fl]
	if !ok {
		var err error
		if k, err = s.knowledge.GetFaultline(ctx, fl); err != nil {
			return domain.ScoreInput{}, FaultlineKnowledge{}, err
		}
		cache.knowledge[fl] = k
	}
	req, ok := cache.reqs[f.ReleaseID()]
	if !ok {
		req = defaultRequirements()
		if s.reqs != nil {
			var err error
			if req, err = s.reqs.ResolvedRequirements(ctx, f.ReleaseID()); err != nil {
				return domain.ScoreInput{}, FaultlineKnowledge{}, err
			}
		}
		cache.reqs[f.ReleaseID()] = req
	}
	return domain.ScoreInput{CVE: f.CVE(), Candidates: cands, Requirements: req, KEV: k.KEV}, k, nil
}

func defaultRequirements() domain.ScoreRequirements {
	x := domain.RequirementValue{Value: "X", Level: "default"}
	return domain.ScoreRequirements{CR: x, IR: x, AR: x}
}

// scoreComponent maps a matched component into the selection's view. A published fix is RL:O
// evidence only when it is attributable to this component (the same rule the fix list uses).
func scoreComponent(c domain.MatchedComponent, k FaultlineKnowledge) domain.ScoreComponent {
	sc := domain.ScoreComponent{
		PURL: c.PURL, Name: c.Name, Version: c.Version, SourcePackage: c.Source,
		ClaimClass: c.ClaimClass, VerdictState: c.VerdictState,
	}
	for _, f := range k.Fixes {
		if fixAppliesTo(f, c) {
			sc.FixApplicable = true
			break
		}
	}
	return sc
}

// FindingScoreView is the provenance read of one Finding.
type FindingScoreView struct {
	FindingID  string
	CVE        string
	Rollup     *RollupRevision
	Components []ScoreRevision
	History    []ScoreRevisionSummary
}

// Score reads the stored assessment of a Finding. A Finding not yet assessed returns a view with
// no roll-up: "not yet assessed" is not a score.
func (s *ScoreService) Score(ctx context.Context, id domain.FindingID) (FindingScoreView, error) {
	f, err := s.findings.GetByID(ctx, id)
	if err != nil {
		return FindingScoreView{}, err
	}
	comps, rollup, err := s.store.CurrentScores(ctx, string(id))
	if err != nil {
		return FindingScoreView{}, err
	}
	hist, err := s.store.ScoreHistory(ctx, string(id))
	if err != nil {
		return FindingScoreView{}, err
	}
	active := map[string]bool{}
	for _, c := range f.ActiveComponents() {
		active[c.PURL] = true
	}
	current := make([]ScoreRevision, 0, len(comps))
	for _, c := range comps {
		if active[c.PURL] {
			current = append(current, c)
		}
	}
	sort.Slice(current, func(i, j int) bool { return current[i].PURL < current[j].PURL })
	return FindingScoreView{FindingID: string(id), CVE: f.CVE(), Rollup: rollup, Components: current, History: hist}, nil
}

// DefaultScoreSweepInterval is the re-assessment cadence (THEMIS_SCORE_SWEEP_INTERVAL).
const DefaultScoreSweepInterval = 6 * time.Hour

// ScoreSweep re-assesses every Finding (EDR 8.2 triggers, in shadow): each run reads the current
// inputs and writes a revision only where something changed, naming the cause from the
// difference. Re-running it is harmless, which is what makes an at-least-once trigger safe.
type ScoreSweep struct {
	svc  *ScoreService
	page int
}

// NewScoreSweep builds the sweep.
func NewScoreSweep(svc *ScoreService) *ScoreSweep { return &ScoreSweep{svc: svc, page: 200} }

// SweepResult counts one run.
type SweepResult struct {
	Assessed int
	Changed  int
	Failed   int
	// FirstError is the first per-Finding failure, for the log.
	FirstError error
}

// Run assesses every Finding once. A per-Finding failure is counted and the sweep goes on; only
// a failure to list Findings ends the run.
func (s *ScoreSweep) Run(ctx context.Context) (SweepResult, error) {
	var res SweepResult
	cache := newScoreCache()
	after := ""
	for {
		ids, err := s.svc.store.FindingIDsAfter(ctx, after, s.page)
		if err != nil {
			return res, err
		}
		for _, id := range ids {
			changed, err := s.svc.assess(ctx, domain.FindingID(id), cache)
			res.Assessed++
			switch {
			case err != nil:
				res.Failed++
				if res.FirstError == nil {
					res.FirstError = err
				}
			case changed:
				res.Changed++
			}
		}
		if len(ids) < s.page {
			return res, nil
		}
		after = ids[len(ids)-1]
	}
}

// RunEvery runs the sweep now and then on every tick until ctx ends.
func (s *ScoreSweep) RunEvery(ctx context.Context, every time.Duration, report func(SweepResult, error)) {
	r, err := s.Run(ctx)
	report(r, err)
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r, err := s.Run(ctx)
			report(r, err)
		}
	}
}
