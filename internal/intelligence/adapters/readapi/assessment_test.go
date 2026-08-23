package readapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// GetReleasePosture is the runtime's read of the release-scoped Domain Projection: ONE call, and
// the `source` package rides along — the only key that joins a component to its published fix, so
// a plan can name the package an operator actually upgrades (AI-GROUND-1).
func TestGetReleasePosture(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
		  {"finding_id":"f1","cve":"CVE-2007-4559","stance":"","residual_priority":97,
		   "effective_priority":97,
		   "components":[{"purl":"pkg:rpm/rocky/python3-ply@3.9","name":"python3-ply",
		                  "version":"3.9","ecosystem":"rpm","source":"python-ply"}]},
		  {"finding_id":"f2","cve":"CVE-1","stance":"not_affected","residual_priority":0,
		   "effective_priority":80,"components":[]}
		]`))
	}))
	defer srv.Close()

	got, err := NewAssessmentClient(srv.URL, srv.Client()).
		GetReleasePosture(context.Background(), "rel-1")
	if err != nil {
		t.Fatalf("GetReleasePosture: %v", err)
	}
	if path != "/api/v1/releases/rel-1/posture" {
		t.Errorf("path = %q", path)
	}
	if got.ReleaseID != "rel-1" || len(got.Entries) != 2 {
		t.Fatalf("posture = %+v", got)
	}
	if got.OutstandingCount() != 1 {
		t.Errorf("outstanding = %d, want 1 — the decided Finding is not work", got.OutstandingCount())
	}
	c := got.Entries[0].Components
	if len(c) != 1 || c[0].Source != "python-ply" {
		t.Errorf("components = %+v, want the source package carried", c)
	}
}

func TestGetReleasePostureErrors(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	if _, err := NewAssessmentClient(bad.URL, bad.Client()).
		GetReleasePosture(context.Background(), "rel-1"); err == nil {
		t.Error("a non-200 must error rather than yield an empty posture — an empty one reads as 'nothing outstanding'")
	}

	junk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{not json"))
	}))
	defer junk.Close()
	if _, err := NewAssessmentClient(junk.URL, junk.Client()).
		GetReleasePosture(context.Background(), "rel-1"); err == nil {
		t.Error("malformed JSON must error")
	}

	if _, err := NewAssessmentClient("http://ex\x00ample", nil).
		GetReleasePosture(context.Background(), "rel-1"); err == nil {
		t.Error("an unbuildable request must error")
	}
	if _, err := NewAssessmentClient("http://127.0.0.1:1", &http.Client{}).
		GetReleasePosture(context.Background(), "rel-1"); err == nil {
		t.Error("an unreachable Governance must error")
	}
}

// The comparison read (AI-CMP-1): one call, buckets mapped verbatim; Governance's honesty
// guard (422/502) and transport failures surface as errors, never as empty diffs.
func TestGetReleaseComparison(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/releases/rel-a/compare/rel-b" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{
			"baseline_release_id":"rel-a","candidate_release_id":"rel-b",
			"fixed":[{"finding_id":"f1","cve":"CVE-1","residual_priority":90,"effective_priority":90,
				"components":[{"purl":"pkg:rpm/x@1","name":"x","version":"1","source":"src-x"}]}],
			"new":[],
			"persisting":[{"finding_id":"f3","cve":"CVE-3","stance":"affected","residual_priority":70,"effective_priority":70}]
		}`))
	}))
	defer srv.Close()

	c := NewAssessmentClient(srv.URL, srv.Client())
	cmp, err := c.GetReleaseComparison(context.Background(), "rel-a", "rel-b")
	if err != nil {
		t.Fatalf("GetReleaseComparison: %v", err)
	}
	if cmp.BaselineID != "rel-a" || cmp.CandidateID != "rel-b" {
		t.Errorf("ids = %s/%s", cmp.BaselineID, cmp.CandidateID)
	}
	if len(cmp.Fixed) != 1 || cmp.Fixed[0].CVE != "CVE-1" || cmp.Fixed[0].Components[0].Source != "src-x" {
		t.Errorf("fixed = %+v", cmp.Fixed)
	}
	if len(cmp.New) != 0 || len(cmp.Persisting) != 1 || cmp.Persisting[0].Stance != "affected" {
		t.Errorf("new/persisting = %+v / %+v", cmp.New, cmp.Persisting)
	}

	// The guard's refusal (or any non-200) is an error the gateway turns into no-grounding.
	if _, err := c.GetReleaseComparison(context.Background(), "rel-a", "rel-nope"); err == nil {
		t.Error("non-200 must return an error")
	}
}

func TestGetReleaseComparison_MalformedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{not-json`))
	}))
	defer srv.Close()
	if _, err := NewAssessmentClient(srv.URL, nil).GetReleaseComparison(context.Background(), "a", "b"); err == nil {
		t.Error("malformed JSON must return a decode error")
	}
}
