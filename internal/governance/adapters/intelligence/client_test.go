package intelligence

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientProduced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/capabilities/recommend_position/invoke" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"capability":"recommend_position@v1","stance":"affected",` +
			`"confidence":0.8,"reasoning":"KEV-listed"}`))
	}))
	defer srv.Close()

	rec, produced, _, err := NewClient(srv.URL, srv.Client()).RecommendPosition(context.Background(), "F1")
	if err != nil || !produced {
		t.Fatalf("expected produced; got %v, %v", produced, err)
	}
	if rec.Stance != "affected" || rec.Confidence != 0.8 || rec.Capability != "recommend_position@v1" {
		t.Errorf("recommendation = %+v", rec)
	}
}

func TestClientNoProposal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	_, produced, _, err := NewClient(srv.URL, srv.Client()).RecommendPosition(context.Background(), "F1")
	if err != nil || produced {
		t.Errorf("204 → no proposal, nil err; got %v, %v", produced, err)
	}
}

func TestClientErrors(t *testing.T) {
	boom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer boom.Close()
	if _, _, _, err := NewClient(boom.URL, boom.Client()).RecommendPosition(context.Background(), "F1"); err == nil {
		t.Error("500 should error")
	}

	badJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{not json"))
	}))
	defer badJSON.Close()
	if _, _, _, err := NewClient(badJSON.URL, badJSON.Client()).RecommendPosition(context.Background(), "F1"); err == nil {
		t.Error("bad JSON should error")
	}

	if _, _, _, err := NewClient("http://ex\x00ample", nil).RecommendPosition(context.Background(), "F1"); err == nil {
		t.Error("bad URL should error")
	}
	if _, _, _, err := NewClient("http://127.0.0.1:1", &http.Client{}).RecommendPosition(context.Background(), "F1"); err == nil {
		t.Error("transport error expected")
	}
}

func TestNoopAdvisor(t *testing.T) {
	_, produced, _, err := NoopAdvisor{}.RecommendPosition(context.Background(), "F1")
	if err != nil || produced {
		t.Errorf("no-op must decline; got %v, %v", produced, err)
	}
}

// The 204's two headers stay two fields. They were once concatenated into
// "<reason>: <detail>", which turned a closed enum into free text and made every
// exact-match consumer miss — a `business_invalid` safety refusal reached the operator as
// "the Gateway stated no reason" (DEF_GOV_AI_REASON_COMPOSITE_BREAKS_TAXONOMY).
func TestClientKeepsReasonAndDetailApart(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Themis-AI-Reason", "business_invalid")
		w.Header().Set("X-Themis-AI-Detail", "ungrounded citation: httpd-2.4.37-65")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	_, produced, no, err := NewClient(srv.URL, srv.Client()).RecommendPosition(context.Background(), "F1")
	if err != nil || produced {
		t.Fatalf("204 → no proposal, nil err; got %v, %v", produced, err)
	}
	if no.Reason != "business_invalid" {
		t.Errorf("Reason = %q, want the bare taxonomy word — a consumer switches on it", no.Reason)
	}
	if no.Detail != "ungrounded citation: httpd-2.4.37-65" {
		t.Errorf("Detail = %q, want the elaboration preserved beside the reason", no.Detail)
	}
}
