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

	rec, produced, err := NewClient(srv.URL, srv.Client()).RecommendPosition(context.Background(), "F1")
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
	_, produced, err := NewClient(srv.URL, srv.Client()).RecommendPosition(context.Background(), "F1")
	if err != nil || produced {
		t.Errorf("204 → no proposal, nil err; got %v, %v", produced, err)
	}
}

func TestClientErrors(t *testing.T) {
	boom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer boom.Close()
	if _, _, err := NewClient(boom.URL, boom.Client()).RecommendPosition(context.Background(), "F1"); err == nil {
		t.Error("500 should error")
	}

	badJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{not json"))
	}))
	defer badJSON.Close()
	if _, _, err := NewClient(badJSON.URL, badJSON.Client()).RecommendPosition(context.Background(), "F1"); err == nil {
		t.Error("bad JSON should error")
	}

	if _, _, err := NewClient("http://ex\x00ample", nil).RecommendPosition(context.Background(), "F1"); err == nil {
		t.Error("bad URL should error")
	}
	if _, _, err := NewClient("http://127.0.0.1:1", &http.Client{}).RecommendPosition(context.Background(), "F1"); err == nil {
		t.Error("transport error expected")
	}
}

func TestNoopAdvisor(t *testing.T) {
	_, produced, err := NoopAdvisor{}.RecommendPosition(context.Background(), "F1")
	if err != nil || produced {
		t.Errorf("no-op must decline; got %v, %v", produced, err)
	}
}
