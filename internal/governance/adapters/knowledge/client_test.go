package knowledge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
)

func TestGetFaultlineHappy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/faultlines/fl-1" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"id":"fl-1","cve":"CVE-2024-1","view":{
			"severity":"high","cvss_score":7.5,"epss":0.42,"kev":true,"exploit_public":true,
			"affected_ranges":["< 2.0"],"fixed_versions":["2.0"],"range_trust":"observed"}}`))
	}))
	defer srv.Close()

	got, err := NewClient(srv.URL, srv.Client()).GetFaultline(context.Background(), "fl-1")
	if err != nil {
		t.Fatalf("GetFaultline: %v", err)
	}
	if got.FaultlineID != "fl-1" || got.CVE != "CVE-2024-1" || got.Severity != "high" {
		t.Errorf("identity/headline = %+v", got)
	}
	if got.CVSSScore != 7.5 || got.EPSS != 0.42 || !got.KEV || !got.ExploitPublic {
		t.Errorf("signals = %+v", got)
	}
	if len(got.AffectedRanges) != 1 || len(got.FixedVersions) != 1 {
		t.Errorf("ranges/fixes = %+v", got)
	}
	// The class rides along so a consumer knows what the range evidence is worth — a verdict
	// computed from these ranges inherits it (EDR-TRUST-01 T3).
	if got.RangeTrust != value.TrustObserved {
		t.Errorf("RangeTrust = %q, want %q", got.RangeTrust, value.TrustObserved)
	}
}

// A trailing slash on the configured base URL must not produce a double slash — a silently
// 404-ing seam would degrade every projection to "no enrichment" without an obvious cause.
func TestGetFaultlineTrimsBaseURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/faultlines/fl-1" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"id":"fl-1"}`))
	}))
	defer srv.Close()
	if _, err := NewClient(srv.URL+"/", srv.Client()).GetFaultline(context.Background(), "fl-1"); err != nil {
		t.Fatalf("GetFaultline: %v", err)
	}
}

func TestGetFaultlineErrors(t *testing.T) {
	notFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer notFound.Close()
	if _, err := NewClient(notFound.URL, notFound.Client()).GetFaultline(context.Background(), "fl-1"); err == nil {
		t.Error("a 404 must error so the caller can degrade deliberately")
	}

	badJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{`))
	}))
	defer badJSON.Close()
	if _, err := NewClient(badJSON.URL, badJSON.Client()).GetFaultline(context.Background(), "fl-1"); err == nil {
		t.Error("malformed JSON must error")
	}

	if _, err := NewClient("http://127.0.0.1:1", nil).GetFaultline(context.Background(), "fl-1"); err == nil {
		t.Error("a transport failure must error")
	}
	if _, err := NewClient("://bad", nil).GetFaultline(context.Background(), "fl-1"); err == nil {
		t.Error("a malformed URL must error")
	}
}

// carrier_products must cross the seam (EDR-ATTRIBUTION-01 D10). Knowledge has always held it —
// it is what every component's claim class is decided against — but it never left the context,
// so Governance could see that NO component matched a carrier and still not say WHICH carrier
// went unmatched.
func TestGetFaultlineCarriesTheCarrierProducts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"fl-1","cve":"CVE-2026-33006","view":{
			"severity":"medium","carrier_products":["http_server","apache_http_server"]}}`))
	}))
	defer srv.Close()

	got, err := NewClient(srv.URL, srv.Client()).GetFaultline(context.Background(), "fl-1")
	if err != nil {
		t.Fatalf("GetFaultline: %v", err)
	}
	if len(got.CarrierProducts) != 2 || got.CarrierProducts[0] != "http_server" {
		t.Errorf("CarrierProducts = %v, want both carriers the card named, in order", got.CarrierProducts)
	}
}
