package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// compareProjection serves a distinct posture per release id — the compare read joins two.
type compareProjection struct {
	postures map[string][]app.PostureEntry
	errFor   map[string]error
}

func (f compareProjection) ReleasePosture(_ context.Context, rel string) ([]app.PostureEntry, error) {
	if err := f.errFor[rel]; err != nil {
		return nil, err
	}
	return f.postures[rel], nil
}

func (f compareProjection) FaultlineBlastRadius(context.Context, string) ([]string, error) {
	return nil, nil
}

type fakeEvidence struct {
	has map[string]bool
	err error
}

func (f fakeEvidence) HasEvidence(_ context.Context, rel string) (bool, error) {
	return f.has[rel], f.err
}

func entry(cve string, base int, stance domain.Stance) app.PostureEntry {
	return app.PostureEntry{FindingID: domain.FindingID("fnd-" + cve), CVE: cve, BaseScore: base, Stance: stance}
}

func TestCompareReleases_Buckets(t *testing.T) {
	proj := compareProjection{postures: map[string][]app.PostureEntry{
		// Baseline: two that get fixed (out-of-order priorities, to observe the sort),
		// one that persists.
		"rel-a": {entry("CVE-1", 10, ""), entry("CVE-2", 90, ""), entry("CVE-3", 50, "")},
		// Candidate: the persisting one + a brand-new one.
		"rel-b": {entry("CVE-3", 60, ""), entry("CVE-4", 30, "")},
	}}
	rs := app.NewReadService(newRepo(), proj, nil, 0).WithEvidence(fakeEvidence{has: map[string]bool{"rel-a": true, "rel-b": true}})

	cmp, err := rs.CompareReleases(context.Background(), "rel-a", "rel-b")
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if cmp.BaselineReleaseID != "rel-a" || cmp.CandidateReleaseID != "rel-b" {
		t.Errorf("ids = %s / %s", cmp.BaselineReleaseID, cmp.CandidateReleaseID)
	}
	// Fixed carries the BASELINE's rows, sorted by residual priority descending.
	if len(cmp.Fixed) != 2 || cmp.Fixed[0].CVE != "CVE-2" || cmp.Fixed[1].CVE != "CVE-1" {
		t.Errorf("fixed = %+v", cmp.Fixed)
	}
	if len(cmp.New) != 1 || cmp.New[0].CVE != "CVE-4" {
		t.Errorf("new = %+v", cmp.New)
	}
	// Persisting carries the CANDIDATE's row — its state there, not the baseline's.
	if len(cmp.Persisting) != 1 || cmp.Persisting[0].CVE != "CVE-3" || cmp.Persisting[0].BaseScore != 60 {
		t.Errorf("persisting = %+v", cmp.Persisting)
	}
}

func TestCompareReleases_SortFallsBackToEffective(t *testing.T) {
	// Two suppressed Findings both read residual 0 — the ordering must then fall back to
	// effective priority, so the severer suppression still lists first.
	proj := compareProjection{postures: map[string][]app.PostureEntry{
		"rel-a": {entry("CVE-1", 20, domain.StanceNotAffected), entry("CVE-2", 80, domain.StanceNotAffected)},
		"rel-b": {},
	}}
	rs := app.NewReadService(newRepo(), proj, nil, 0).WithEvidence(fakeEvidence{has: map[string]bool{"rel-a": true, "rel-b": true}})

	cmp, err := rs.CompareReleases(context.Background(), "rel-a", "rel-b")
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if len(cmp.Fixed) != 2 || cmp.Fixed[0].CVE != "CVE-2" || cmp.Fixed[0].ResidualPriority != 0 {
		t.Errorf("fixed = %+v", cmp.Fixed)
	}
}

func TestCompareReleases_RefusesWithoutEvidence(t *testing.T) {
	proj := compareProjection{postures: map[string][]app.PostureEntry{}}

	// No seam wired at all ⇒ fail-closed.
	rs := app.NewReadService(newRepo(), proj, nil, 0)
	if _, err := rs.CompareReleases(context.Background(), "rel-a", "rel-b"); !errors.Is(err, app.ErrEvidenceUnavailable) {
		t.Errorf("nil seam: err = %v", err)
	}

	// Evidence unreachable ⇒ fail-closed, wrapping the sentinel.
	rs = app.NewReadService(newRepo(), proj, nil, 0).WithEvidence(fakeEvidence{err: errors.New("boom")})
	if _, err := rs.CompareReleases(context.Background(), "rel-a", "rel-b"); !errors.Is(err, app.ErrEvidenceUnavailable) {
		t.Errorf("unreachable: err = %v", err)
	}

	// A side with no evidence is named — absence there proves nothing.
	rs = app.NewReadService(newRepo(), proj, nil, 0).WithEvidence(fakeEvidence{has: map[string]bool{"rel-b": true}})
	_, err := rs.CompareReleases(context.Background(), "rel-a", "rel-b")
	var noEv *app.NoEvidenceError
	if !errors.As(err, &noEv) || len(noEv.ReleaseIDs) != 1 || noEv.ReleaseIDs[0] != "rel-a" {
		t.Fatalf("missing baseline: err = %v", err)
	}
	if !strings.Contains(noEv.Error(), "rel-a") {
		t.Errorf("error message should name the release: %q", noEv.Error())
	}

	// Both sides missing ⇒ both named.
	rs = app.NewReadService(newRepo(), proj, nil, 0).WithEvidence(fakeEvidence{})
	_, err = rs.CompareReleases(context.Background(), "rel-a", "rel-b")
	if !errors.As(err, &noEv) || len(noEv.ReleaseIDs) != 2 {
		t.Errorf("both missing: err = %v", err)
	}
}

func TestCompareReleases_PostureErrorsPropagate(t *testing.T) {
	ev := fakeEvidence{has: map[string]bool{"rel-a": true, "rel-b": true}}
	dbDown := errors.New("db down")

	rs := app.NewReadService(newRepo(), compareProjection{errFor: map[string]error{"rel-a": dbDown}}, nil, 0).WithEvidence(ev)
	if _, err := rs.CompareReleases(context.Background(), "rel-a", "rel-b"); !errors.Is(err, dbDown) {
		t.Errorf("baseline posture error: %v", err)
	}

	rs = app.NewReadService(newRepo(), compareProjection{errFor: map[string]error{"rel-b": dbDown}}, nil, 0).WithEvidence(ev)
	if _, err := rs.CompareReleases(context.Background(), "rel-a", "rel-b"); !errors.Is(err, dbDown) {
		t.Errorf("candidate posture error: %v", err)
	}
}
