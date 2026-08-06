package readapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The runtime's single grounding read: one business-named Domain Projection, decoded whole.
// Nothing here composes two responses — that composition is Governance's, which is exactly
// what stopped the runtime orchestrating (EDR-TRUST-01 T10).
func TestAssessmentClientHappy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/findings/F1/assessment" {
			t.Errorf("path = %s, want the assessment projection", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{
			"finding":{"id":"F1","release_id":"R1","faultline_id":"FL1","cve":"CVE-2024-0001","stage":"identified",
			           "components":[{"purl":"pkg:golang/x@1.0.0"},{"purl":"pkg:npm/y@2.0.0"}]},
			"knowledge":{"faultline_id":"FL1","cve":"CVE-2024-0001","severity":"high","cvss_score":7.5,
			             "epss":0.42,"kev":true,"exploit_public":true,
			             "affected_ranges":["< 2.0"],"fixed_versions":["2.0"]}
		}`))
	}))
	defer srv.Close()

	got, err := NewAssessmentClient(srv.URL, srv.Client()).GetAssessment(context.Background(), "F1")
	if err != nil {
		t.Fatalf("GetAssessment: %v", err)
	}
	if got.Finding.ID != "F1" || got.Finding.FaultlineID != "FL1" || len(got.Finding.Components) != 2 {
		t.Errorf("finding half = %+v", got.Finding)
	}
	if got.Knowledge.Severity != "high" || !got.Knowledge.KEV || len(got.Knowledge.AffectedRanges) != 1 {
		t.Errorf("knowledge half = %+v", got.Knowledge)
	}
}

// A projection whose knowledge half is absent still decodes — Governance degrades to the
// Finding alone when Knowledge is unreachable, and the runtime must carry that through rather
// than treat it as a failed read. The reasoning then proceeds with less grounding, which is
// the honest outcome.
func TestAssessmentClientToleratesMissingKnowledge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"finding":{"id":"F1","faultline_id":"FL1"}}`))
	}))
	defer srv.Close()

	got, err := NewAssessmentClient(srv.URL, srv.Client()).GetAssessment(context.Background(), "F1")
	if err != nil {
		t.Fatalf("GetAssessment: %v", err)
	}
	if got.Finding.ID != "F1" {
		t.Errorf("finding half lost: %+v", got.Finding)
	}
	if got.Knowledge.ID != "" {
		t.Errorf("knowledge half = %+v, want empty", got.Knowledge)
	}
}

func TestAssessmentClientErrors(t *testing.T) {
	notFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer notFound.Close()
	if _, err := NewAssessmentClient(notFound.URL, notFound.Client()).GetAssessment(context.Background(), "F1"); err == nil {
		t.Error("a 404 projection must be an error, not an empty grounding")
	}

	badJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{`))
	}))
	defer badJSON.Close()
	if _, err := NewAssessmentClient(badJSON.URL, badJSON.Client()).GetAssessment(context.Background(), "F1"); err == nil {
		t.Error("malformed JSON must error")
	}

	if _, err := NewAssessmentClient("http://127.0.0.1:1", nil).GetAssessment(context.Background(), "F1"); err == nil {
		t.Error("a transport failure must error")
	}
	if _, err := NewAssessmentClient("://bad", nil).GetAssessment(context.Background(), "F1"); err == nil {
		t.Error("a malformed URL must error")
	}
}
