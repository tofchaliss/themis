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

// EDR-VEX-02 D14: a `fixed` statement's advisory and build survive the read seam.
func TestGetFaultlineCarriesFixedStatementAdvisoryAndBuild(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"fl-1","cve":"CVE-2022-30632","view":{"severity":"medium","applicabilities":[
			{"package":"git-lfs","status":"fixed","justification":"Red Hat: fixed in git-lfs-0:2.13.3-3.el8_6 (RHSA-2022:7129)","scope_family":"enterprise-linux","scope_major":"8","advisory":"RHSA-2022:7129","fixed_version":"git-lfs-0:2.13.3-3.el8_6"},
			{"package":"osbuild-composer","status":"will_not_fix","justification":"Red Hat: will not fix in Red Hat Enterprise Linux 8","scope_family":"enterprise-linux","scope_major":"8"}]}}`))
	}))
	defer srv.Close()
	got, err := NewClient(srv.URL, srv.Client()).GetFaultline(context.Background(), "fl-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Applicabilities) != 2 {
		t.Fatalf("applicabilities = %+v", got.Applicabilities)
	}
	if a := got.Applicabilities[0]; a.Status != "fixed" || a.Advisory != "RHSA-2022:7129" || a.FixedVersion != "git-lfs-0:2.13.3-3.el8_6" || a.Scope.Major != "8" {
		t.Errorf("fixed statement = %+v", a)
	}
	if a := got.Applicabilities[1]; a.Status != "will_not_fix" || a.Advisory != "" {
		t.Errorf("will_not_fix statement = %+v", a)
	}
}

// KN-RANGE-ECO-1: the statements ride the read seam with their world intact.
func TestGetFaultlineCarriesRangeStatements(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"fl-1","cve":"CVE-2019-17596","view":{"affected_ranges":["<1.13.2","<21.1.1.1.0"],
			"affected_range_statements":[{"ecosystem":"go","package":"stdlib","range":"<1.13.2"},{"range":"<21.1.1.1.0"}]}}`))
	}))
	defer srv.Close()
	got, err := NewClient(srv.URL, srv.Client()).GetFaultline(context.Background(), "fl-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.RangeStatements) != 2 || got.RangeStatements[0].Ecosystem != "go" || got.RangeStatements[0].Package != "stdlib" || got.RangeStatements[1].Ecosystem != "" {
		t.Fatalf("statements = %+v", got.RangeStatements)
	}
}

// EDR-INCIDENT-01 D2: a CVE resolves to its card or to "no card" (404), an advisory to the
// cards carrying it (an unseen one is an empty list); other statuses and bad bodies are errors.
func TestWatchResolution(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path + "?" + r.URL.RawQuery {
		case "/api/v1/faultlines?cve=CVE-2026-0001":
			_, _ = w.Write([]byte(`{"id":"fl-1","cve":"CVE-2026-0001","view":{"fixes":[{"package":"kernel","version":"0:3.el8","ecosystem":"rpm"}]}}`))
		case "/api/v1/faultlines?cve=CVE-2026-0404":
			w.WriteHeader(http.StatusNotFound)
		case "/api/v1/faultlines?cve=CVE-2026-0500":
			w.WriteHeader(http.StatusInternalServerError)
		case "/api/v1/faultlines?cve=CVE-2026-0666":
			_, _ = w.Write([]byte(`{not-json`))
		case "/api/v1/faultlines/by-advisory?id=RHSA-2026%3A0001":
			_, _ = w.Write([]byte(`[{"id":"fl-1","cve":"CVE-2026-0001","view":{}},{"id":"fl-2","cve":"CVE-2026-0002","view":{}}]`))
		case "/api/v1/faultlines/by-advisory?id=RHSA-2026%3A0000":
			_, _ = w.Write([]byte(`[]`))
		case "/api/v1/faultlines/by-advisory?id=RHSA-2026%3A0666":
			_, _ = w.Write([]byte(`{not-json`))
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()
	c := NewClient(srv.URL, srv.Client())
	ctx := context.Background()

	card, ok, err := c.FaultlineByCVE(ctx, "CVE-2026-0001")
	if err != nil || !ok || card.FaultlineID != "fl-1" || len(card.Fixes) != 1 || card.Fixes[0].Package != "kernel" {
		t.Errorf("by cve = %+v ok %v err %v", card, ok, err)
	}
	if _, ok, err := c.FaultlineByCVE(ctx, "CVE-2026-0404"); err != nil || ok {
		t.Errorf("no card: ok %v err %v", ok, err)
	}
	if _, _, err := c.FaultlineByCVE(ctx, "CVE-2026-0500"); err == nil {
		t.Error("500 swallowed")
	}
	if _, _, err := c.FaultlineByCVE(ctx, "CVE-2026-0666"); err == nil {
		t.Error("bad body swallowed")
	}
	cards, err := c.FaultlinesByAdvisory(ctx, "RHSA-2026:0001")
	if err != nil || len(cards) != 2 || cards[1].CVE != "CVE-2026-0002" {
		t.Errorf("by advisory = %+v err %v", cards, err)
	}
	if cards, err := c.FaultlinesByAdvisory(ctx, "RHSA-2026:0000"); err != nil || len(cards) != 0 {
		t.Errorf("unseen = %+v err %v", cards, err)
	}
	if _, err := c.FaultlinesByAdvisory(ctx, "RHSA-2026:0503"); err == nil {
		t.Error("503 swallowed")
	}
	if _, err := c.FaultlinesByAdvisory(ctx, "RHSA-2026:0666"); err == nil {
		t.Error("bad body swallowed")
	}
	bad := NewClient("http://127.0.0.1:1", nil)
	if _, _, err := bad.FaultlineByCVE(ctx, "CVE-2026-0001"); err == nil {
		t.Error("transport error swallowed")
	}
	if _, err := bad.FaultlinesByAdvisory(ctx, "RHSA-2026:0001"); err == nil {
		t.Error("transport error swallowed")
	}
	broken := NewClient("://bad", nil)
	if _, _, err := broken.FaultlineByCVE(ctx, "CVE-2026-0001"); err == nil {
		t.Error("bad URL swallowed")
	}
	if _, err := broken.FaultlinesByAdvisory(ctx, "RHSA-2026:0001"); err == nil {
		t.Error("bad URL swallowed")
	}
}

// EDR-REBUILD-01 D30: the fix verdicts ride the read seam as Knowledge recorded them. A fix
// value this client does not know, and a `known` that names no bound, read as unknown — never
// as a known fix. Other statuses, bad bodies and transport failures are errors.
func TestReleaseFixVerdicts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/releases/rel-1/fix-verdicts":
			_, _ = w.Write([]byte(`[
				{"faultline_id":"fl-1","cve":"CVE-2026-0001","purl":"pkg:rpm/redhat/kernel@4.18.0-1.el8","state":"open","fix":"known","behind":["0:4.18.0-2.el8"]},
				{"faultline_id":"fl-2","cve":"CVE-2026-0002","purl":"pkg:rpm/redhat/bash@4.4-1.el8","state":"open","fix":"none","behind":[]},
				{"faultline_id":"fl-3","cve":"CVE-2026-0003","purl":"pkg:npm/left-pad@1.0.0","state":"open","fix":"unknown","behind":[]},
				{"faultline_id":"fl-4","cve":"CVE-2026-0004","purl":"pkg:rpm/redhat/zlib@1.2-1.el8","state":"open","fix":"known","behind":[]},
				{"faultline_id":"fl-5","cve":"CVE-2026-0005","purl":"pkg:rpm/redhat/curl@7.61-1.el8","state":"open","fix":"certainly","behind":["x"]},
				{"faultline_id":"fl-6","cve":"CVE-2026-0006","purl":"pkg:rpm/redhat/python3-ply@3.9-9.el8","state":"open","fix":"other_stream","behind":["0:3.11-10.module+el8.10.0+1+a"]},
				{"faultline_id":"fl-7","cve":"CVE-2026-0007","purl":"pkg:rpm/redhat/perl@5.26-1.el8","state":"open","fix":"other_stream","behind":[]}]`))
		case "/api/v1/releases/rel-empty/fix-verdicts":
			_, _ = w.Write([]byte(`[]`))
		case "/api/v1/releases/rel-bad/fix-verdicts":
			_, _ = w.Write([]byte(`{not-json`))
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()
	c := NewClient(srv.URL, srv.Client())
	ctx := context.Background()

	got, err := c.ReleaseFixVerdicts(ctx, "rel-1")
	if err != nil || len(got) != 7 {
		t.Fatalf("verdicts = %+v err %v", got, err)
	}
	if got[5].Fix != "other_stream" || len(got[5].FixedVersions) != 1 || got[6].Fix != "unknown" {
		t.Errorf("other stream = %+v", got[5:])
	}
	if got[0].Fix != "known" || got[0].FaultlineID != "fl-1" || got[0].PURL != "pkg:rpm/redhat/kernel@4.18.0-1.el8" ||
		len(got[0].FixedVersions) != 1 || got[0].FixedVersions[0] != "0:4.18.0-2.el8" {
		t.Errorf("known = %+v", got[0])
	}
	if got[1].Fix != "none" || got[2].Fix != "unknown" || got[3].Fix != "unknown" || got[4].Fix != "unknown" || got[4].FixedVersions != nil {
		t.Errorf("others = %+v", got[1:5])
	}
	if got, err := c.ReleaseFixVerdicts(ctx, "rel-empty"); err != nil || len(got) != 0 {
		t.Errorf("empty = %+v err %v", got, err)
	}
	if _, err := c.ReleaseFixVerdicts(ctx, "rel-503"); err == nil {
		t.Error("503 swallowed")
	}
	if _, err := c.ReleaseFixVerdicts(ctx, "rel-bad"); err == nil {
		t.Error("bad body swallowed")
	}
	if _, err := NewClient("http://127.0.0.1:1", nil).ReleaseFixVerdicts(ctx, "rel-1"); err == nil {
		t.Error("transport error swallowed")
	}
	if _, err := NewClient("http://bad\x7f", nil).ReleaseFixVerdicts(ctx, "rel-1"); err == nil {
		t.Error("request build error swallowed")
	}
}
