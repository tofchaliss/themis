package http_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	knhttp "github.com/themis-project/themis/internal/knowledge/adapters/http"
	"github.com/themis-project/themis/internal/knowledge/adapters/store"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

type fakeRepo struct {
	card  domain.Faultline
	found bool
	err   error
}

func (r fakeRepo) GetByCVE(_ context.Context, cve string) (domain.Faultline, bool, error) {
	if r.err != nil {
		return domain.Faultline{}, false, r.err
	}
	if r.found && r.card.CVE().String() == cve {
		return r.card, true, nil
	}
	return domain.Faultline{}, false, nil
}

func (r fakeRepo) GetByID(_ context.Context, id domain.FaultlineID) (domain.Faultline, error) {
	if r.err != nil {
		return domain.Faultline{}, r.err
	}
	if r.found && r.card.ID() == id {
		return r.card, nil
	}
	return domain.Faultline{}, store.ErrNotFound
}

func (r fakeRepo) Save(context.Context, domain.Faultline, bool, int, []app.OutboxNote) error {
	return nil
}

type fakeProjection struct {
	releases []string
	err      error
}

func (f fakeProjection) AffectedReleases(context.Context, string) ([]string, error) {
	return f.releases, f.err
}

func sampleCard(t *testing.T) domain.Faultline {
	t.Helper()
	cve, _ := value.NewCVEID("CVE-2024-1")
	f, _ := domain.NewFaultline("fl-1", cve)
	c, _ := value.NewCVSS(7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
	p, _ := domain.NewVulnFactsProposal("nvd", time.Unix(1_700_000_000, 0),
		domain.VulnFacts{Severity: value.SeverityHigh, CVSS: c, AffectedRanges: []string{"<3.0"}})
	f.FoldProposal(p, domain.NewPrecedence("nvd"), domain.NewTrustPolicy(nil))
	return f
}

func server(t *testing.T, repo app.Repository, proj app.ProjectionReader) *httptest.Server {
	t.Helper()
	return feedServer(t, repo, proj, fakeFeedStore{})
}

// feedServer serves the full handler backed by a specific feed-health store (for GET /feeds).
func feedServer(t *testing.T, repo app.Repository, proj app.ProjectionReader, feeds app.FeedHealthStore) *httptest.Server {
	t.Helper()
	health := app.NewFeedHealthService(feeds, feedClock{})
	read := app.NewReadService(repo, proj)
	if rl, ok := repo.(app.RecentLister); ok {
		read = read.WithRecent(rl)
	}
	srv := httptest.NewServer(knhttp.NewHandler(read, health).Router())
	t.Cleanup(srv.Close)
	return srv
}

// recentRepo is a repository that also lists recent cards (GUI-16).
type recentRepo struct {
	fakeRepo
	recent []app.RecentFaultline
	limit  int
	rerr   error
}

func (r *recentRepo) RecentFaultlines(_ context.Context, limit int) ([]app.RecentFaultline, error) {
	r.limit = limit
	return r.recent, r.rerr
}

// GUI-16: the recent list carries the full card beside its creation time, the limit is clamped
// by the app, an unwired lister is a 503 and a store failure a 500.
func TestGetRecentFaultlines(t *testing.T) {
	card := sampleCard(t)
	repo := &recentRepo{fakeRepo: fakeRepo{card: card, found: true}, recent: []app.RecentFaultline{{Faultline: card, CreatedAt: time.Unix(1_700_000_000, 0).UTC()}}}
	srv := server(t, repo, fakeProjection{})

	status, body := get(t, srv.URL+"/faultlines/recent?limit=5000")
	if status != http.StatusOK {
		t.Fatalf("status = %d: %s", status, body)
	}
	var rows []struct {
		CreatedAt time.Time `json:"created_at"`
		Card      struct {
			Cve  string `json:"cve"`
			View struct {
				Severity string `json:"severity"`
			} `json:"view"`
		} `json:"card"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Card.Cve != "CVE-2024-1" || rows[0].Card.View.Severity != "high" || rows[0].CreatedAt.Unix() != 1_700_000_000 {
		t.Errorf("rows = %+v", rows)
	}
	if repo.limit != app.RecentMaxLimit {
		t.Errorf("limit = %d, want the cap %d", repo.limit, app.RecentMaxLimit)
	}
	if status, _ := get(t, srv.URL+"/faultlines/recent"); status != http.StatusOK || repo.limit != app.RecentDefaultLimit {
		t.Errorf("default: status %d, limit %d", status, repo.limit)
	}
	repo.rerr = errors.New("db down")
	if status, _ := get(t, srv.URL+"/faultlines/recent"); status != http.StatusInternalServerError {
		t.Errorf("store failure status = %d, want 500", status)
	}
	plain := server(t, fakeRepo{card: card, found: true}, fakeProjection{})
	if status, _ := get(t, plain.URL+"/faultlines/recent"); status != http.StatusServiceUnavailable {
		t.Errorf("unwired status = %d, want 503", status)
	}
}

type feedClock struct{}

func (feedClock) Now() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

type fakeFeedStore struct {
	rows []app.FeedHealthRow
	err  error
}

func (fakeFeedStore) RecordFeedSuccess(context.Context, string, int, time.Time) error { return nil }
func (fakeFeedStore) RecordFeedFailure(context.Context, string, int, time.Time) error { return nil }
func (f fakeFeedStore) FeedHealthRows(context.Context) ([]app.FeedHealthRow, error) {
	return f.rows, f.err
}

func get(t *testing.T, url string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var buf [4096]byte
	n, _ := resp.Body.Read(buf[:])
	return resp.StatusCode, buf[:n]
}

func TestGetFaultlineById(t *testing.T) {
	srv := server(t, fakeRepo{card: sampleCard(t), found: true}, fakeProjection{})

	status, body := get(t, srv.URL+"/faultlines/fl-1")
	if status != http.StatusOK {
		t.Fatalf("status = %d: %s", status, body)
	}
	var v struct {
		Cve, Stage string
		View       struct {
			Severity  string  `json:"severity"`
			CvssScore float32 `json:"cvss_score"`
		}
		Proposals []map[string]any
	}
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	if v.Cve != "CVE-2024-1" || v.Stage != "enriched" || v.View.Severity != "high" || v.View.CvssScore != 7.5 {
		t.Errorf("view = %+v", v)
	}
	if len(v.Proposals) != 1 {
		t.Errorf("proposals = %d, want 1", len(v.Proposals))
	}

	// Unknown id → 404.
	if status, _ := get(t, srv.URL+"/faultlines/nope"); status != http.StatusNotFound {
		t.Errorf("unknown id status = %d, want 404", status)
	}
}

func TestGetFaultlineByCVE(t *testing.T) {
	srv := server(t, fakeRepo{card: sampleCard(t), found: true}, fakeProjection{})
	if status, _ := get(t, srv.URL+"/faultlines?cve=CVE-2024-1"); status != http.StatusOK {
		t.Errorf("by-cve status = %d, want 200", status)
	}
	// Unknown CVE → 404.
	srv2 := server(t, fakeRepo{found: false}, fakeProjection{})
	if status, _ := get(t, srv2.URL+"/faultlines?cve=CVE-9999-9"); status != http.StatusNotFound {
		t.Errorf("unknown cve status = %d, want 404", status)
	}
}

func TestGetFaultlineReleases(t *testing.T) {
	srv := server(t, fakeRepo{card: sampleCard(t), found: true}, fakeProjection{releases: []string{"rel-1", "rel-2"}})
	status, body := get(t, srv.URL+"/faultlines/fl-1/releases")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	var rels []string
	if err := json.Unmarshal(body, &rels); err != nil {
		t.Fatal(err)
	}
	if len(rels) != 2 {
		t.Errorf("releases = %v, want 2", rels)
	}
}

func TestReadErrors(t *testing.T) {
	boom := errors.New("db down")
	srv := server(t, fakeRepo{err: boom}, fakeProjection{err: boom})
	for _, path := range []string{"/faultlines/fl-1", "/faultlines?cve=CVE-2024-1", "/faultlines/fl-1/releases"} {
		if status, _ := get(t, srv.URL+path); status != http.StatusInternalServerError {
			t.Errorf("%s status = %d, want 500", path, status)
		}
	}
}

func TestGetFeedHealth(t *testing.T) {
	recent := feedClock{}.Now().Add(-1 * time.Hour) // within every tier threshold
	feeds := fakeFeedStore{rows: []app.FeedHealthRow{
		{Source: "nvd", Tier: 1, LastSuccessAt: &recent, ConsecutiveFailures: 0}, // healthy
		{Source: "osv", Tier: 2, LastSuccessAt: &recent, ConsecutiveFailures: 3}, // Tier-2 failing → degraded
	}}
	srv := feedServer(t, fakeRepo{}, fakeProjection{}, feeds)

	status, body := get(t, srv.URL+"/feeds")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", status, body)
	}
	var rep struct {
		SignalsStale  bool     `json:"signals_stale"`
		DegradedFeeds []string `json:"degraded_feeds"`
		Feeds         []struct {
			Source string `json:"source"`
			Status string `json:"status"`
			Tier   int    `json:"tier"`
		} `json:"feeds"`
	}
	if err := json.Unmarshal(body, &rep); err != nil {
		t.Fatalf("decode: %v; body=%s", err, body)
	}
	if rep.SignalsStale {
		t.Errorf("signals_stale = true, want false (no Tier-1 stale)")
	}
	if len(rep.Feeds) != 2 {
		t.Fatalf("feeds = %d, want 2", len(rep.Feeds))
	}
	if len(rep.DegradedFeeds) != 1 || rep.DegradedFeeds[0] != "osv" {
		t.Errorf("degraded_feeds = %v, want [osv]", rep.DegradedFeeds)
	}
}

func TestGetFeedHealthError(t *testing.T) {
	srv := feedServer(t, fakeRepo{}, fakeProjection{}, fakeFeedStore{err: errors.New("db down")})
	if status, _ := get(t, srv.URL+"/feeds"); status != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", status)
	}
}

// The read API must expose fixes ATTRIBUTED to their package, not only the flat union — that
// union is what let a dashboard print "upgrade python3-ply 3.9 to 0.1.7", a different package's
// fix (KN-FIX-1). A consumer can only act on the attributed form.
func TestGetFaultlineById_ExposesAttributedFixes(t *testing.T) {
	cveID, _ := value.NewCVEID("CVE-2024-1")
	f, _ := domain.NewFaultline("fl-1", cveID)
	c, _ := value.NewCVSS(7.5, "")
	p, _ := domain.NewVulnFactsProposal("osv", time.Unix(1_700_000_000, 0), domain.VulnFacts{
		Severity: value.SeverityHigh, CVSS: c,
		Fixes: []domain.FixedVersion{
			{Package: "glibc", Version: "2.28-251.el8_10.38"},
			{Version: "9.9.9"}, // unattributed: the source did not say which package
		},
	})
	f.FoldProposal(p, domain.NewPrecedence("osv"), domain.NewTrustPolicy(nil))
	srv := server(t, fakeRepo{card: f, found: true}, fakeProjection{})

	status, body := get(t, srv.URL+"/faultlines/fl-1")
	if status != http.StatusOK {
		t.Fatalf("status = %d: %s", status, body)
	}
	var v struct {
		View struct {
			FixedVersions []string `json:"fixed_versions"`
			Fixes         []struct {
				Package string `json:"package"`
				Version string `json:"version"`
			} `json:"fixes"`
		} `json:"view"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.View.Fixes) != 2 {
		t.Fatalf("fixes = %+v, want both entries", v.View.Fixes)
	}
	var glibc, bare int
	for _, fx := range v.View.Fixes {
		if fx.Package == "glibc" && fx.Version == "2.28-251.el8_10.38" {
			glibc++
		}
		if fx.Package == "" && fx.Version == "9.9.9" {
			bare++
		}
	}
	if glibc != 1 || bare != 1 {
		t.Errorf("fixes = %+v, want the attributed one and the unattributed one distinguishable", v.View.Fixes)
	}
	// The flat list still carries everything, for "is a fix published at all?".
	if len(v.View.FixedVersions) != 2 {
		t.Errorf("fixed_versions = %v, want both versions", v.View.FixedVersions)
	}
}

// A card with no fixes omits the field entirely, so it is byte-identical on the wire to one
// written before `fixes` existed.
func TestGetFaultlineById_OmitsFixesWhenThereAreNone(t *testing.T) {
	srv := server(t, fakeRepo{card: sampleCard(t), found: true}, fakeProjection{})
	_, body := get(t, srv.URL+"/faultlines/fl-1")
	if bytes.Contains(body, []byte(`"fixes"`)) {
		t.Errorf("empty fixes must be omitted, got: %s", body)
	}
}

// --- the unresolved-components endpoint (EDR-IDENTITY-01 D6) -------------------------------

type idFacts struct {
	kind, release string
	found         bool
}

func (f idFacts) EvidenceFacts(context.Context, string) (string, string, bool, error) {
	return f.kind, f.release, f.found, nil
}

type idSource struct{ props []app.ScannerProposal }

func (s idSource) ScannerProposals(context.Context, string) ([]app.ScannerProposal, int, error) {
	return s.props, 0, nil
}

func identityServer(t *testing.T, facts app.EvidenceFactsSource, src app.ScannerReportSource) *httptest.Server {
	t.Helper()
	fold := app.NewFaultlineService(fakeRepo{}, idGenStub{}, feedClock{},
		domain.NewPrecedence("nvd"), domain.NewTrustPolicy(nil))
	scan := app.NewScannerReportService(src, fold, noopMatches{}, feedClock{}).WithEvidenceFacts(facts)
	health := app.NewFeedHealthService(fakeFeedStore{}, feedClock{})
	srv := httptest.NewServer(
		knhttp.NewHandler(app.NewReadService(fakeRepo{}, fakeProjection{}), health).WithScanner(scan).Router())
	t.Cleanup(srv.Close)
	return srv
}

type idGenStub struct{}

func (idGenStub) NewID() string { return "fl-1" }

type noopMatches struct{}

func (noopMatches) RecordMatch(context.Context, app.Match) (bool, error) { return false, nil }

func TestGetUnresolvedComponents(t *testing.T) {
	cveID, err := value.NewCVEID("CVE-2023-31122")
	if err != nil {
		t.Fatal(err)
	}
	prop, err := domain.NewVulnFactsProposal("scanner", feedClock{}.Now(),
		domain.VulnFacts{Severity: value.SeverityHigh})
	if err != nil {
		t.Fatal(err)
	}
	src := idSource{props: []app.ScannerProposal{{
		CVE: cveID, Proposal: prop, Origin: "scanner/cortex",
		Component: app.InventoryComponent{PURL: "app:httpd", Name: "httpd", Version: "2.4.57"},
	}}}

	t.Run("200 with the verbatim observed identifier", func(t *testing.T) {
		srv := identityServer(t, idFacts{kind: "scanner-report", release: "rel-1", found: true}, src)
		status, body := get(t, srv.URL+"/scanner-reports/ev-1/unresolved")
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", status, body)
		}
		var rep struct {
			ReleaseID  string `json:"release_id"`
			Resolved   int    `json:"resolved"`
			Unresolved int    `json:"unresolved"`
			Components []struct {
				Name         string `json:"name"`
				ObservedPurl string `json:"observed_purl"`
				Reason       string `json:"reason"`
				Origin       string `json:"origin"`
			} `json:"components"`
		}
		if jerr := json.Unmarshal([]byte(body), &rep); jerr != nil {
			t.Fatalf("decode: %v; body=%s", jerr, body)
		}
		if rep.ReleaseID != "rel-1" || rep.Unresolved != 1 || len(rep.Components) != 1 {
			t.Fatalf("report = %+v", rep)
		}
		c := rep.Components[0]
		if c.Name != "httpd" || c.ObservedPurl != "app:httpd" || c.Reason != "no_candidate" {
			t.Errorf("component = %+v, want the observed string carried verbatim", c)
		}
		if c.Origin != "scanner/cortex" {
			t.Errorf("origin = %q, want the observing engine", c.Origin)
		}
	})

	t.Run("404 for an unknown id — never an empty 200", func(t *testing.T) {
		srv := identityServer(t, idFacts{}, src)
		if status, body := get(t, srv.URL+"/scanner-reports/ev-ghost/unresolved"); status != http.StatusNotFound {
			t.Errorf("status = %d, want 404; body=%s", status, body)
		}
	})

	t.Run("409 for a document that carries no observations", func(t *testing.T) {
		srv := identityServer(t, idFacts{kind: "sbom", release: "rel-1", found: true}, src)
		if status, body := get(t, srv.URL+"/scanner-reports/ev-sbom/unresolved"); status != http.StatusConflict {
			t.Errorf("status = %d, want 409; body=%s", status, body)
		}
	})

	t.Run("500 when the query is unwired — refusing beats reporting zero", func(t *testing.T) {
		health := app.NewFeedHealthService(fakeFeedStore{}, feedClock{})
		srv := httptest.NewServer(
			knhttp.NewHandler(app.NewReadService(fakeRepo{}, fakeProjection{}), health).Router())
		t.Cleanup(srv.Close)
		if status, _ := get(t, srv.URL+"/scanner-reports/ev-1/unresolved"); status != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500 — 'not wired' must not read as 'all clear'", status)
		}
	})
}

// EDR-VEX-02 D5: the vendor-stated product scope rides the card's read API, so Governance can
// determine applicability and SHOW it beside the vendor's words. Emitted as two flat fields, and
// omitted entirely when the vendor supplied no readable scope — a consumer must read that absence
// as `unknown` (uncertainty), never as a product mismatch (D4).
func TestGetFaultline_CarriesVendorScope(t *testing.T) {
	cve, _ := value.NewCVEID("CVE-2023-31122")
	f, _ := domain.NewFaultline("fl-scope", cve)
	scoped, err := domain.NewApplicabilityProposal("redhat", feedClock{}.Now(), domain.Applicability{
		Package: "httpd", Status: "not_affected",
		Justification: "Red Hat: not affected in Red Hat Enterprise Linux 7",
		Scope:         value.ProductScope{Family: value.FamilyEnterpriseLinux, Major: "7"},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.FoldProposal(scoped, domain.NewPrecedence("redhat"), domain.NewTrustPolicy(nil))
	bare, err := domain.NewApplicabilityProposal("vexfeed", feedClock{}.Now(), domain.Applicability{
		Package: "httpd", Status: "not_affected", Justification: "no scope stated",
	})
	if err != nil {
		t.Fatal(err)
	}
	f.FoldProposal(bare, domain.NewPrecedence("redhat", "vexfeed"), domain.NewTrustPolicy(nil))

	srv := server(t, fakeRepo{card: f, found: true}, fakeProjection{})
	status, body := get(t, srv.URL+"/faultlines/fl-scope")
	if status != http.StatusOK {
		t.Fatalf("status = %d; body=%s", status, body)
	}
	var out struct {
		View struct {
			Applicabilities []struct {
				Package     string `json:"package"`
				ScopeFamily string `json:"scope_family"`
				ScopeMajor  string `json:"scope_major"`
			} `json:"applicabilities"`
		} `json:"view"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode: %v; body=%s", err, body)
	}
	if len(out.View.Applicabilities) != 2 {
		t.Fatalf("applicabilities = %d, want 2 — a scoped and an unscoped statement", len(out.View.Applicabilities))
	}
	var sawScoped, sawBare bool
	for _, a := range out.View.Applicabilities {
		switch {
		case a.ScopeFamily == value.FamilyEnterpriseLinux && a.ScopeMajor == "7":
			sawScoped = true
		case a.ScopeFamily == "" && a.ScopeMajor == "":
			sawBare = true
		}
	}
	if !sawScoped {
		t.Error("the vendor's stated scope (enterprise-linux 7) did not reach the wire")
	}
	if !sawBare {
		t.Error("an unscoped statement must still be carried, with an empty scope meaning unknown")
	}
}

// The carrier products must reach the wire (EDR-ATTRIBUTION-01 D10). They decide every
// component's claim class inside Knowledge, and without them a consuming context can see that
// nothing matched a carrier but cannot say WHICH carrier it failed to place — which is the whole
// difference between "attribution gap" as a label and as a statement a reviewer can act on.
func TestGetFaultline_CarriesTheCarrierProducts(t *testing.T) {
	cve, _ := value.NewCVEID("CVE-2026-33006")
	f, _ := domain.NewFaultline("fl-carrier", cve)
	p, err := domain.NewVulnFactsProposal("nvd", feedClock{}.Now(), domain.VulnFacts{
		Severity:        value.SeverityMedium,
		CarrierProducts: []string{"http_server"},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.FoldProposal(p, domain.NewPrecedence("nvd"), domain.NewTrustPolicy(nil))

	srv := server(t, fakeRepo{card: f, found: true}, fakeProjection{})
	status, body := get(t, srv.URL+"/faultlines/fl-carrier")
	if status != http.StatusOK {
		t.Fatalf("status = %d; body=%s", status, body)
	}
	var out struct {
		View struct {
			CarrierProducts []string `json:"carrier_products"`
		} `json:"view"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode: %v; body=%s", err, body)
	}
	if len(out.View.CarrierProducts) != 1 || out.View.CarrierProducts[0] != "http_server" {
		t.Errorf("carrier_products = %v, want the card's carrier on the wire", out.View.CarrierProducts)
	}
}

// KN-RANGE-ECO-1: the read API carries each range's world beside the flat list; a world-less
// statement omits the empty fields.
func TestGetFaultlineById_CarriesRangeStatements(t *testing.T) {
	cve, _ := value.NewCVEID("CVE-2019-17596")
	f, _ := domain.NewFaultline("fl-1", cve)
	c, _ := value.NewCVSS(7.5, "")
	p, _ := domain.NewVulnFactsProposal("osv", time.Unix(1_700_000_000, 0), domain.VulnFacts{Severity: value.SeverityHigh, CVSS: c,
		AffectedRanges:  []string{"<1.13.2", "<=4.23.1f"},
		RangeStatements: []value.RangeStatement{{Ecosystem: "go", Package: "stdlib", Range: "<1.13.2"}, {Range: "<=4.23.1f"}}})
	f.FoldProposal(p, domain.NewPrecedence("nvd"), domain.NewTrustPolicy(nil))
	srv := server(t, fakeRepo{card: f, found: true}, fakeProjection{})

	status, body := get(t, srv.URL+"/faultlines/fl-1")
	if status != http.StatusOK {
		t.Fatalf("status = %d: %s", status, body)
	}
	var v struct {
		View struct {
			AffectedRanges []string         `json:"affected_ranges"`
			Statements     []map[string]any `json:"affected_range_statements"`
		} `json:"view"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.View.AffectedRanges) != 2 || len(v.View.Statements) != 2 {
		t.Fatalf("view = %+v", v.View)
	}
	// Sorted: the world-less one first (empty ecosystem), then go/stdlib.
	if _, has := v.View.Statements[0]["ecosystem"]; has || v.View.Statements[0]["range"] != "<=4.23.1f" {
		t.Fatalf("world-less statement = %+v, want only range", v.View.Statements[0])
	}
	if v.View.Statements[1]["ecosystem"] != "go" || v.View.Statements[1]["package"] != "stdlib" || v.View.Statements[1]["range"] != "<1.13.2" {
		t.Fatalf("go statement = %+v", v.View.Statements[1])
	}
}

type fakeSanity struct {
	flags []app.SuspectFanout
	err   error
}

func (f fakeSanity) SuspectFanouts(context.Context) ([]app.SuspectFanout, error) {
	return f.flags, f.err
}

// KN-SANITY-1: GET /sanity lists the guard's flags; unwired, it answers empty and says so.
func TestGetSanityFlags(t *testing.T) {
	at := time.Unix(1_700_000_000, 0).UTC()
	h := knhttp.NewHandler(app.NewReadService(fakeRepo{}, fakeProjection{}), app.NewFeedHealthService(fakeFeedStore{}, feedClock{})).
		WithSanity(fakeSanity{flags: []app.SuspectFanout{{ReleaseID: "rel-1", PURL: "pkg:golang/stdlib@vgo1.27.1", Version: "vgo1.27.1", Ecosystem: "golang", CVEs: 165, Reason: "suspect fan-out", FlaggedAt: at}}})
	srv := httptest.NewServer(h.Router())
	defer srv.Close()
	status, body := get(t, srv.URL+"/sanity")
	if status != http.StatusOK {
		t.Fatalf("status = %d: %s", status, body)
	}
	var flags []map[string]any
	if err := json.Unmarshal(body, &flags); err != nil || len(flags) != 1 || flags[0]["cves"] != float64(165) || flags[0]["purl"] != "pkg:golang/stdlib@vgo1.27.1" {
		t.Fatalf("flags = %+v err=%v", flags, err)
	}
	bad := httptest.NewServer(knhttp.NewHandler(app.NewReadService(fakeRepo{}, fakeProjection{}), app.NewFeedHealthService(fakeFeedStore{}, feedClock{})).WithSanity(fakeSanity{err: errors.New("db")}).Router())
	defer bad.Close()
	if status, _ := get(t, bad.URL+"/sanity"); status != http.StatusInternalServerError {
		t.Fatalf("store failure status = %d, want 500", status)
	}
	none := httptest.NewServer(knhttp.NewHandler(app.NewReadService(fakeRepo{}, fakeProjection{}), app.NewFeedHealthService(fakeFeedStore{}, feedClock{})).Router())
	defer none.Close()
	resp, err := http.Get(none.URL + "/sanity")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Themis-Sanity") != "not-wired" {
		t.Fatalf("unwired: status %d header %q", resp.StatusCode, resp.Header.Get("X-Themis-Sanity"))
	}
}

// --- GUI-16 layer 2: the live latest-published read -----------------------------------

type fakePublishedSrc struct {
	calls int
	rows  []app.PublishedCVE
	err   error
}

func (f *fakePublishedSrc) PublishedSince(context.Context, time.Time) ([]app.PublishedCVE, error) {
	f.calls++
	return f.rows, f.err
}

func publishedServer(t *testing.T, src app.PublishedSource) (*httptest.Server, *fakePublishedSrc) {
	t.Helper()
	fs, _ := src.(*fakePublishedSrc)
	repo := fakeRepo{card: sampleCard(t), found: true}
	read := app.NewReadService(repo, fakeProjection{})
	health := app.NewFeedHealthService(fakeFeedStore{}, feedClock{})
	h := knhttp.NewHandler(read, health)
	if src != nil {
		h = h.WithPublished(app.NewPublishedService(src, repo, feedClock{}))
	}
	srv := httptest.NewServer(h.Router())
	t.Cleanup(srv.Close)
	return srv, fs
}

// The read is live and unstored, flags the carded CVE, clamps the window, answers 503 with no
// source and 502 when the source fails, and a repeat within the cache life asks the source once.
func TestGetPublishedRecently(t *testing.T) {
	src := &fakePublishedSrc{rows: []app.PublishedCVE{
		{CVE: "CVE-2024-1", Published: time.Unix(1_700_000_000, 0).UTC(), Summary: "known", Severity: "high", Score: 7.5},
		{CVE: "CVE-2026-9", Published: time.Unix(1_700_003_600, 0).UTC(), Summary: "fresh"},
	}}
	srv, _ := publishedServer(t, src)
	status, body := get(t, srv.URL+"/faultlines/published-recently?days=99")
	if status != http.StatusOK {
		t.Fatalf("status = %d: %s", status, body)
	}
	var rows []struct {
		Cve       string   `json:"cve"`
		Carded    bool     `json:"carded"`
		Summary   *string  `json:"summary"`
		Severity  *string  `json:"severity"`
		CvssScore *float32 `json:"cvss_score"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Cve != "CVE-2026-9" || rows[0].Carded || rows[0].Severity != nil || rows[0].CvssScore != nil ||
		rows[1].Cve != "CVE-2024-1" || !rows[1].Carded || *rows[1].Severity != "high" || *rows[1].CvssScore != 7.5 {
		t.Errorf("rows = %+v", rows)
	}
	// Cached: a second read within five minutes does not ask the source again.
	if s, _ := get(t, srv.URL+"/faultlines/published-recently?days=99"); s != http.StatusOK || src.calls != 1 {
		t.Errorf("second read: status %d, source calls %d (want 1)", s, src.calls)
	}
	// A different window is a different entry.
	if s, _ := get(t, srv.URL+"/faultlines/published-recently"); s != http.StatusOK || src.calls != 2 {
		t.Errorf("default window: status %d, source calls %d (want 2)", s, src.calls)
	}
	failing, _ := publishedServer(t, &fakePublishedSrc{err: errors.New("nvd down")})
	if s, _ := get(t, failing.URL+"/faultlines/published-recently"); s != http.StatusBadGateway {
		t.Errorf("source failure status = %d, want 502", s)
	}
	none, _ := publishedServer(t, nil)
	if s, _ := get(t, none.URL+"/faultlines/published-recently"); s != http.StatusServiceUnavailable {
		t.Errorf("no source status = %d, want 503", s)
	}
}
