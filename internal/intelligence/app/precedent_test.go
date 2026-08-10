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
