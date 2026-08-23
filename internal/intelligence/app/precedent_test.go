package app

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

// recordingSemantic is an Embedder + VectorIndex that records what it was asked, so a test can
// assert the QUERY SEMANTICS (which release was excluded, how many neighbours were requested)
// and not merely the result.
type recordingSemantic struct {
	out      []domain.PrecedentPosition
	embedErr error

	embedCalls int
	embedText  string
	searchK    int
	searchExcl string
	searches   int
}

func (r *recordingSemantic) Embed(_ context.Context, text string) ([]float32, error) {
	r.embedCalls++
	r.embedText = text
	if r.embedErr != nil {
		return nil, r.embedErr
	}
	return []float32{1, 0}, nil
}

func (r *recordingSemantic) Model() string { return "rec" }

func (r *recordingSemantic) Search(_ []float32, k int, excl string) []domain.PrecedentPosition {
	r.searches++
	r.searchK, r.searchExcl = k, excl
	return r.out
}

type recordingFallback struct {
	out        []domain.PrecedentPosition
	err        error
	calls      int
	gotFL      string
	gotExclude string
}

func (r *recordingFallback) GetPrecedents(_ context.Context, fl, excl string) ([]domain.PrecedentPosition, error) {
	r.calls++
	r.gotFL, r.gotExclude = fl, excl
	return r.out, r.err
}

func subjectQuery() PrecedentQuery {
	return PrecedentQuery{
		Severity:    "high",
		Components:  []string{"pkg:golang/openssl"},
		FaultlineID: "FL1",
		ReleaseID:   "R1",
	}
}

func TestRetrievePrefersSemanticAndSkipsFallback(t *testing.T) {
	sem := &recordingSemantic{out: []domain.PrecedentPosition{{ReleaseID: "R2", SourceCVE: "CVE-2", Score: 0.9}}}
	fb := &recordingFallback{out: []domain.PrecedentPosition{{ReleaseID: "R9"}}}
	s := NewPrecedentService(sem, sem, fb, 3)

	got := s.Retrieve(context.Background(), subjectQuery())

	if len(got) != 1 || got[0].ReleaseID != "R2" {
		t.Fatalf("got %+v, want the semantic neighbour R2", got)
	}
	if fb.calls != 0 {
		t.Errorf("fallback must not run when semantic retrieval found precedent; calls=%d", fb.calls)
	}
	if sem.embedText != "pkg:golang/openssl high" {
		t.Errorf("embedded %q, want the SubjectText composition", sem.embedText)
	}
	if sem.searchK != 3 {
		t.Errorf("searchK = %d, want the service default 3", sem.searchK)
	}
	if sem.searchExcl != "R1" {
		t.Errorf("excluded %q, want the subject's own release R1", sem.searchExcl)
	}
}

func TestRetrieveFallsBackWhenSemanticEmpty(t *testing.T) {
	sem := &recordingSemantic{out: nil} // cold index
	fb := &recordingFallback{out: []domain.PrecedentPosition{{ReleaseID: "R9", Stance: "affected"}}}
	s := NewPrecedentService(sem, sem, fb, 0)

	got := s.Retrieve(context.Background(), subjectQuery())

	if len(got) != 1 || got[0].ReleaseID != "R9" {
		t.Fatalf("got %+v, want the exact-CVE fallback R9", got)
	}
	if fb.gotFL != "FL1" || fb.gotExclude != "R1" {
		t.Errorf("fallback asked (%q,%q), want (FL1,R1)", fb.gotFL, fb.gotExclude)
	}
}

func TestRetrieveTopKOverridesTheServiceDefault(t *testing.T) {
	sem := &recordingSemantic{out: []domain.PrecedentPosition{{ReleaseID: "R2"}}}
	s := NewPrecedentService(sem, sem, nil, 5)

	q := subjectQuery()
	q.TopK = 2
	s.Retrieve(context.Background(), q)

	if sem.searchK != 2 {
		t.Errorf("searchK = %d, want the per-query override 2", sem.searchK)
	}
}

func TestNewPrecedentServiceDefaultsTopK(t *testing.T) {
	sem := &recordingSemantic{out: []domain.PrecedentPosition{{ReleaseID: "R2"}}}
	s := NewPrecedentService(sem, sem, nil, 0)

	s.Retrieve(context.Background(), subjectQuery())

	if sem.searchK != defaultTopK {
		t.Errorf("searchK = %d, want the default %d", sem.searchK, defaultTopK)
	}
}

// IncludeSameRelease is query semantics: it widens the candidate set, and it must widen BOTH
// sources or the two would disagree about what "same release" means.
func TestIncludeSameReleaseDropsTheExclusionOnBothSources(t *testing.T) {
	sem := &recordingSemantic{out: []domain.PrecedentPosition{{ReleaseID: "R1"}}}
	s := NewPrecedentService(sem, sem, nil, 5)
	q := subjectQuery()
	q.IncludeSameRelease = true

	s.Retrieve(context.Background(), q)
	if sem.searchExcl != "" {
		t.Errorf("semantic exclusion = %q, want empty when same-release is requested", sem.searchExcl)
	}

	cold := &recordingSemantic{out: nil}
	fb := &recordingFallback{out: []domain.PrecedentPosition{{ReleaseID: "R1"}}}
	s2 := NewPrecedentService(cold, cold, fb, 5)
	s2.Retrieve(context.Background(), q)
	if fb.gotExclude != "" {
		t.Errorf("fallback exclusion = %q, want empty when same-release is requested", fb.gotExclude)
	}
}

func TestRetrieveEmptySubjectTextSkipsTheEmbedder(t *testing.T) {
	sem := &recordingSemantic{out: []domain.PrecedentPosition{{ReleaseID: "R2"}}}
	fb := &recordingFallback{out: []domain.PrecedentPosition{{ReleaseID: "R9"}}}
	s := NewPrecedentService(sem, sem, fb, 5)

	// No components, no severity ⇒ SubjectText is "" ⇒ nothing to be similar to.
	got := s.Retrieve(context.Background(), PrecedentQuery{FaultlineID: "FL1", ReleaseID: "R1"})

	if sem.embedCalls != 0 {
		t.Errorf("embedder called %d times for an empty subject, want 0", sem.embedCalls)
	}
	if len(got) != 1 || got[0].ReleaseID != "R9" {
		t.Errorf("got %+v, want the fallback to still answer", got)
	}
}

func TestRetrieveDegradesOnEmbedError(t *testing.T) {
	sem := &recordingSemantic{embedErr: errors.New("embedder down")}
	s := NewPrecedentService(sem, sem, nil, 5)

	if got := s.Retrieve(context.Background(), subjectQuery()); len(got) != 0 {
		t.Errorf("got %+v, want no precedent", got)
	}
	if sem.searches != 0 {
		t.Errorf("index searched %d times after a failed embed, want 0", sem.searches)
	}
}

func TestRetrieveDegradesOnFallbackError(t *testing.T) {
	fb := &recordingFallback{err: errors.New("governance down")}
	s := NewPrecedentService(nil, nil, fb, 5)

	if got := s.Retrieve(context.Background(), subjectQuery()); len(got) != 0 {
		t.Errorf("got %+v, want no precedent on a failed fallback read", got)
	}
}

// A stateless Gateway (no store ⇒ no embedder, no index) must still serve exact-CVE precedent.
func TestRetrieveWithoutSemanticPlaneUsesFallbackOnly(t *testing.T) {
	fb := &recordingFallback{out: []domain.PrecedentPosition{{ReleaseID: "R9"}}}
	s := NewPrecedentService(nil, nil, fb, 5)

	if got := s.Retrieve(context.Background(), subjectQuery()); len(got) != 1 {
		t.Fatalf("got %+v, want the fallback result", got)
	}
}

func TestRetrieveWithNoSourcesReturnsNothing(t *testing.T) {
	s := NewPrecedentService(nil, nil, nil, 5)
	if got := s.Retrieve(context.Background(), subjectQuery()); got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}

// An empty FaultlineID means there is no CVE to look up — the fallback is skipped rather than
// asked for the precedents of nothing. This is the read plan_remediation used to issue.
func TestRetrieveSkipsFallbackWithoutAFaultline(t *testing.T) {
	fb := &recordingFallback{out: []domain.PrecedentPosition{{ReleaseID: "R9"}}}
	s := NewPrecedentService(nil, nil, fb, 5)

	got := s.Retrieve(context.Background(), PrecedentQuery{Severity: "high", ReleaseID: "R1"})

	if fb.calls != 0 {
		t.Errorf("fallback called %d times without a faultline id, want 0", fb.calls)
	}
	if got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}

// --- RetrieveForFinding: the read-API entry point ----------------------------

func assessment() domain.FindingAssessment {
	return domain.FindingAssessment{
		Finding: domain.FindingView{
			ID: "F1", FaultlineID: "FL1", ReleaseID: "R1",
			Components: []string{"pkg:golang/openssl"},
		},
		Knowledge: domain.FaultlineView{ID: "FL1", CVE: "CVE-1", Severity: "high"},
	}
}

func TestQueryFromAssessmentComposesTheSubject(t *testing.T) {
	q := QueryFromAssessment(assessment())
	if q.Severity != "high" || len(q.Components) != 1 || q.FaultlineID != "FL1" || q.ReleaseID != "R1" {
		t.Errorf("query = %+v, want the projection's severity/components/faultline/release", q)
	}
}

func TestRetrieveForFindingResolvesThenRetrieves(t *testing.T) {
	sem := &recordingSemantic{out: []domain.PrecedentPosition{{ReleaseID: "R2", Score: 0.9}}}
	s := NewPrecedentService(sem, sem, nil, 5).WithProjection(fakeProjection{proj: assessment()})

	got, err := s.RetrieveForFinding(context.Background(), "F1", 2, true)

	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(got) != 1 || got[0].ReleaseID != "R2" {
		t.Fatalf("got %+v, want the semantic neighbour", got)
	}
	if sem.embedText != "pkg:golang/openssl high" {
		t.Errorf("embedded %q, want the projection's SubjectText", sem.embedText)
	}
	if sem.searchK != 2 {
		t.Errorf("searchK = %d, want the caller's k=2", sem.searchK)
	}
	if sem.searchExcl != "" {
		t.Errorf("exclusion = %q, want empty for include_same_release", sem.searchExcl)
	}
}

// A missing Finding must be an error, not an empty list — "that Finding does not exist" and
// "no precedent resembles it" are different answers and only one is a 404.
func TestRetrieveForFindingUnknownSubjectErrors(t *testing.T) {
	s := NewPrecedentService(nil, nil, nil, 5).WithProjection(fakeProjection{}) // zero projection

	if _, err := s.RetrieveForFinding(context.Background(), "nope", 0, false); !errors.Is(err, ErrNoSubject) {
		t.Errorf("err = %v, want ErrNoSubject", err)
	}
}

func TestRetrieveForFindingProjectionReadErrorIsNoSubject(t *testing.T) {
	s := NewPrecedentService(nil, nil, nil, 5).
		WithProjection(fakeProjection{err: errors.New("governance down")})

	if _, err := s.RetrieveForFinding(context.Background(), "F1", 0, false); !errors.Is(err, ErrNoSubject) {
		t.Errorf("err = %v, want ErrNoSubject", err)
	}
}

func TestRetrieveForFindingWithoutAProjectionReaderErrors(t *testing.T) {
	s := NewPrecedentService(nil, nil, nil, 5) // Gateway-only wiring: no projection reader

	if _, err := s.RetrieveForFinding(context.Background(), "F1", 0, false); !errors.Is(err, ErrNoSubject) {
		t.Errorf("err = %v, want ErrNoSubject", err)
	}
}

// --- redaction: the output boundary ------------------------------------------

type upperRedactor struct{}

func (upperRedactor) Redact(s string) string { return "REDACTED:" + s }

func TestRedactPrecedentsScrubsOnlyRationale(t *testing.T) {
	in := []domain.PrecedentPosition{
		{ReleaseID: "R2", Stance: "not_affected", SourceCVE: "CVE-2", Component: "pkg:a", Score: 0.9, Rationale: "secret note"},
	}
	out := RedactPrecedents(upperRedactor{}, in)

	if out[0].Rationale != "REDACTED:secret note" {
		t.Errorf("rationale = %q, want it scrubbed", out[0].Rationale)
	}
	got := out[0]
	if got.ReleaseID != "R2" || got.Stance != "not_affected" || got.SourceCVE != "CVE-2" || got.Component != "pkg:a" || got.Score != 0.9 {
		t.Errorf("structural fields must survive redaction: %+v", got)
	}
}

// Redaction is a projection, never a mutation — the caller's slice (and by extension the stored
// Position it was read from) must be untouched.
func TestRedactPrecedentsDoesNotMutateInput(t *testing.T) {
	in := []domain.PrecedentPosition{{ReleaseID: "R2", Rationale: "original"}}
	_ = RedactPrecedents(upperRedactor{}, in)

	if in[0].Rationale != "original" {
		t.Errorf("input mutated: %q", in[0].Rationale)
	}
}

func TestRedactPrecedentsNilRedactorPassesThrough(t *testing.T) {
	in := []domain.PrecedentPosition{{ReleaseID: "R2", Rationale: "original"}}
	if out := RedactPrecedents(nil, in); out[0].Rationale != "original" {
		t.Errorf("nil redactor changed the text: %q", out[0].Rationale)
	}
	if out := RedactPrecedents(upperRedactor{}, nil); out != nil {
		t.Errorf("empty input returned %+v, want nil", out)
	}
}

// --- G-AI-3: delta-aware ranking ------------------------------------------------------

// deltaComparisons fakes the comparison read per precedent release.
type deltaComparisons struct {
	byRelease map[string]domain.ReleaseComparison
	err       error
	calls     int
}

func (d *deltaComparisons) GetReleaseComparison(_ context.Context, _, candidate string) (domain.ReleaseComparison, error) {
	d.calls++
	if d.err != nil {
		return domain.ReleaseComparison{}, d.err
	}
	return d.byRelease[candidate], d.err
}

// bucketsOf builds a comparison whose overlap = persisting/(fixed+new+persisting).
func bucketsOf(fixed, fresh, persisting int) domain.ReleaseComparison {
	mk := func(n int) []domain.PostureEntry {
		out := make([]domain.PostureEntry, n)
		return out
	}
	return domain.ReleaseComparison{BaselineID: "R1", CandidateID: "x",
		Fixed: mk(fixed), New: mk(fresh), Persisting: mk(persisting)}
}

// A high-cosine precedent from a very DIFFERENT release must fall behind a slightly
// lower-cosine one from a near-identical release — the whole point of G-AI-3.
func TestRetrieveDeltaRanksByReleaseOverlap(t *testing.T) {
	sem := &recordingSemantic{out: []domain.PrecedentPosition{
		{ReleaseID: "far", Score: 0.90},  // overlap 0 → weight 0.5 → rank 0.45
		{ReleaseID: "near", Score: 0.80}, // overlap 1 → weight 1.0 → rank 0.80
	}}
	cmpr := &deltaComparisons{byRelease: map[string]domain.ReleaseComparison{
		"far":  bucketsOf(5, 5, 0),
		"near": bucketsOf(0, 0, 10),
	}}
	s := NewPrecedentService(sem, sem, nil, 5).WithComparisons(cmpr)
	got := s.Retrieve(context.Background(), subjectQuery())
	if len(got) != 2 || got[0].ReleaseID != "near" || got[1].ReleaseID != "far" {
		t.Fatalf("order = %+v, want near before far", got)
	}
	if !got[0].OverlapKnown || got[0].ReleaseOverlap != 1.0 {
		t.Errorf("near overlap = %v known=%v", got[0].ReleaseOverlap, got[0].OverlapKnown)
	}
	if got[1].Score != 0.90 {
		t.Error("the stored cosine score must stay the index's, not the weighted rank")
	}
}

// The fallback's exact-CVE precedents (Score 0) rank by the delta weight alone.
func TestRetrieveDeltaRanksTheFallbackToo(t *testing.T) {
	fb := &recordingFallback{out: []domain.PrecedentPosition{
		{ReleaseID: "far"}, {ReleaseID: "near"},
	}}
	cmpr := &deltaComparisons{byRelease: map[string]domain.ReleaseComparison{
		"far":  bucketsOf(9, 0, 1),
		"near": bucketsOf(1, 0, 9),
	}}
	s := NewPrecedentService(nil, nil, fb, 5).WithComparisons(cmpr)
	got := s.Retrieve(context.Background(), subjectQuery())
	if len(got) != 2 || got[0].ReleaseID != "near" {
		t.Fatalf("order = %+v, want near first", got)
	}
}

// Degradation contract: a failing or empty comparison leaves precedent UNWEIGHTED and in
// retrieval order — an outage must never penalize precedent or block retrieval.
func TestRetrieveDeltaDegradesToUnweighted(t *testing.T) {
	for name, cmpr := range map[string]*deltaComparisons{
		"read error":       {err: context.DeadlineExceeded},
		"empty comparison": {byRelease: map[string]domain.ReleaseComparison{}},
	} {
		t.Run(name, func(t *testing.T) {
			sem := &recordingSemantic{out: []domain.PrecedentPosition{
				{ReleaseID: "a", Score: 0.9}, {ReleaseID: "b", Score: 0.8},
			}}
			s := NewPrecedentService(sem, sem, nil, 5).WithComparisons(cmpr)
			got := s.Retrieve(context.Background(), subjectQuery())
			if len(got) != 2 || got[0].ReleaseID != "a" || got[0].OverlapKnown || got[1].OverlapKnown {
				t.Fatalf("%s: got %+v, want retrieval order, overlap unknown", name, got)
			}
		})
	}
}

// One comparison per DISTINCT precedent release; the subject's own release overlaps 1.0
// without a read; a nil seam or empty subject changes nothing.
func TestRetrieveDeltaCachesAndSkips(t *testing.T) {
	sem := &recordingSemantic{out: []domain.PrecedentPosition{
		{ReleaseID: "other", Score: 0.9}, {ReleaseID: "other", Score: 0.7},
		{ReleaseID: "R1", Score: 0.6}, // same release as the subject (IncludeSameRelease case)
		{ReleaseID: "", Score: 0.5},   // no release: nothing to compare against
	}}
	cmpr := &deltaComparisons{byRelease: map[string]domain.ReleaseComparison{"other": bucketsOf(0, 0, 3)}}
	s := NewPrecedentService(sem, sem, nil, 5).WithComparisons(cmpr)
	got := s.Retrieve(context.Background(), subjectQuery())
	if cmpr.calls != 1 {
		t.Errorf("comparison calls = %d, want 1 (cached per distinct release)", cmpr.calls)
	}
	for _, p := range got {
		if p.ReleaseID == "R1" && (!p.OverlapKnown || p.ReleaseOverlap != 1.0) {
			t.Errorf("subject's own release must overlap 1.0 without a read: %+v", p)
		}
		if p.ReleaseID == "" && p.OverlapKnown {
			t.Errorf("a precedent with no release must stay unweighted: %+v", p)
		}
	}

	// Nil seam: pure retrieval order, untouched.
	sem2 := &recordingSemantic{out: []domain.PrecedentPosition{{ReleaseID: "x", Score: 0.9}}}
	if got := NewPrecedentService(sem2, sem2, nil, 5).Retrieve(context.Background(), subjectQuery()); got[0].OverlapKnown {
		t.Error("nil comparison seam must not mark overlap")
	}
	// Empty subject release: nothing to compare FROM.
	sem3 := &recordingSemantic{out: []domain.PrecedentPosition{{ReleaseID: "x", Score: 0.9}}}
	q := subjectQuery()
	q.ReleaseID = ""
	if got := NewPrecedentService(sem3, sem3, nil, 5).WithComparisons(cmpr).Retrieve(context.Background(), q); got[0].OverlapKnown {
		t.Error("no subject release must leave precedent unweighted")
	}
}
