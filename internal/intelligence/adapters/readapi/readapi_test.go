package readapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFindingClientHappy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/findings/F1" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{
			"id":"F1","release_id":"R1","faultline_id":"FL1","cve":"CVE-2024-0001","stage":"identified",
			"components":[{"purl":"pkg:golang/x@1.0.0"},{"purl":""},{"purl":"pkg:npm/y@2.0.0"}]
		}`))
	}))
	defer srv.Close()

	c := NewFindingClient(srv.URL, srv.Client())
	fv, err := c.GetFinding(context.Background(), "F1")
	if err != nil {
		t.Fatalf("GetFinding err: %v", err)
	}
	if fv.ID != "F1" || fv.FaultlineID != "FL1" || fv.CVE != "CVE-2024-0001" {
		t.Errorf("unexpected view %+v", fv)
	}
	if len(fv.Components) != 2 { // empty purl filtered out
		t.Errorf("components = %v, want 2 non-empty purls", fv.Components)
	}
}

func TestFindingClientNotFoundAndErrors(t *testing.T) {
	notFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer notFound.Close()
	c := NewFindingClient(notFound.URL, notFound.Client())
	if fv, err := c.GetFinding(context.Background(), "missing"); err != nil || fv.ID != "" {
		t.Errorf("404 → zero view, nil err; got %+v, %v", fv, err)
	}

	boom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer boom.Close()
	if _, err := NewFindingClient(boom.URL, boom.Client()).GetFinding(context.Background(), "x"); err == nil {
		t.Error("500 should error")
	}

	badJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{not json"))
	}))
	defer badJSON.Close()
	if _, err := NewFindingClient(badJSON.URL, badJSON.Client()).GetFinding(context.Background(), "x"); err == nil {
		t.Error("bad JSON should error")
	}

	if _, err := NewFindingClient("http://ex\x00ample", nil).GetFinding(context.Background(), "x"); err == nil {
		t.Error("bad URL should error")
	}
	if _, err := NewFindingClient("http://127.0.0.1:1", &http.Client{}).GetFinding(context.Background(), "x"); err == nil {
		t.Error("transport error expected")
	}
}

func TestFaultlineClientHappy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/faultlines/FL1" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{
			"id":"FL1","cve":"CVE-2024-0001",
			"view":{"severity":"high","cvss_score":8.1,"epss":0.42,"kev":true,"exploit_public":true,
				"fixed_versions":["1.2.4"],"affected_ranges":["<1.2.4"]}
		}`))
	}))
	defer srv.Close()

	c := NewFaultlineClient(srv.URL, srv.Client())
	fv, err := c.GetFaultline(context.Background(), "FL1")
	if err != nil {
		t.Fatalf("GetFaultline err: %v", err)
	}
	if fv.ID != "FL1" || fv.Severity != "high" || !fv.KEV || !fv.ExploitPublic || !fv.FixAvailable() {
		t.Errorf("unexpected view %+v", fv)
	}
	if fv.EPSS != 0.42 || fv.CVSSScore != 8.1 {
		t.Errorf("scores = %v / %v", fv.EPSS, fv.CVSSScore)
	}
}

func TestFaultlineClientNotFoundAndErrors(t *testing.T) {
	notFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer notFound.Close()
	if fv, err := NewFaultlineClient(notFound.URL, notFound.Client()).GetFaultline(context.Background(), "x"); err != nil || fv.ID != "" {
		t.Errorf("404 → zero view, nil err; got %+v, %v", fv, err)
	}

	boom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer boom.Close()
	if _, err := NewFaultlineClient(boom.URL, boom.Client()).GetFaultline(context.Background(), "x"); err == nil {
		t.Error("502 should error")
	}

	badJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{nope"))
	}))
	defer badJSON.Close()
	if _, err := NewFaultlineClient(badJSON.URL, badJSON.Client()).GetFaultline(context.Background(), "x"); err == nil {
		t.Error("bad JSON should error")
	}

	if _, err := NewFaultlineClient("http://ex\x00ample", nil).GetFaultline(context.Background(), "x"); err == nil {
		t.Error("bad URL should error")
	}
	if _, err := NewFaultlineClient("http://127.0.0.1:1", &http.Client{}).GetFaultline(context.Background(), "x"); err == nil {
		t.Error("transport error expected")
	}
}
