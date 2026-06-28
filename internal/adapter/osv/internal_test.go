package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/domain"
)

func TestExtractAffectedVersionsPairsEventsAndFiltersPackage(t *testing.T) {
	// One advisory affecting curl (fixed in 7.36.0-r0) plus a second entry for a
	// different package with an open range — the open range must not leak into
	// curl's constraints.
	vuln := osvVuln{
		Affected: []struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
			Ranges []struct {
				Events []osvRangeEvent `json:"events"`
			} `json:"ranges"`
			Versions []string `json:"versions"`
		}{
			{
				Package: struct {
					Ecosystem string `json:"ecosystem"`
					Name      string `json:"name"`
				}{Ecosystem: "Alpine", Name: "curl"},
				Ranges: []struct {
					Events []osvRangeEvent `json:"events"`
				}{{Events: []osvRangeEvent{{Introduced: "0"}, {Fixed: "7.36.0-r0"}}}},
			},
			{
				Package: struct {
					Ecosystem string `json:"ecosystem"`
					Name      string `json:"name"`
				}{Ecosystem: "Alpine", Name: "libcurl"},
				Ranges: []struct {
					Events []osvRangeEvent `json:"events"`
				}{{Events: []osvRangeEvent{{Introduced: "0"}}}}, // open, all-versions
			},
		},
	}

	affected := extractAffectedVersions(vuln, "Alpine", "curl")
	if len(affected) != 1 || affected[0] != "< 7.36.0-r0" {
		t.Fatalf("affected = %#v, want [\"< 7.36.0-r0\"] (libcurl open range filtered out)", affected)
	}
	// The bounded range must NOT match a much newer version (the reported bug).
	if domain.VersionMatches(affected, "8.14.1-r2") {
		t.Fatal("curl 8.14.1-r2 must not match a CVE fixed in 7.36.0-r0")
	}
	// A genuinely affected old version still matches.
	if !domain.VersionMatches(affected, "7.10.0-r0") {
		t.Fatal("curl 7.10.0-r0 should match a CVE fixed in 7.36.0-r0")
	}
}

func TestExtractAffectedVersionsFallbacks(t *testing.T) {
	mk := func(eco, name string, events []osvRangeEvent, versions []string) osvVuln {
		v := osvVuln{}
		var item struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
			Ranges []struct {
				Events []osvRangeEvent `json:"events"`
			} `json:"ranges"`
			Versions []string `json:"versions"`
		}
		item.Package.Ecosystem = eco
		item.Package.Name = name
		if events != nil {
			item.Ranges = []struct {
				Events []osvRangeEvent `json:"events"`
			}{{Events: events}}
		}
		item.Versions = versions
		v.Affected = append(v.Affected, item)
		return v
	}

	// No affected entry aligns to the queried package -> preserve recall (*).
	if got := extractAffectedVersions(mk("Alpine", "openssl", []osvRangeEvent{{Fixed: "1"}}, nil), "Alpine", "curl"); len(got) != 1 || got[0] != "*" {
		t.Fatalf("unmatched package = %#v, want [*]", got)
	}
	// Matched package, explicit no-constraint entry -> all versions (*).
	if got := extractAffectedVersions(mk("Alpine", "curl", nil, nil), "Alpine", "curl"); len(got) != 1 || got[0] != "*" {
		t.Fatalf("no-constraint = %#v, want [*]", got)
	}
	// Matched package, unfixed open range -> all versions from 0 (*).
	if got := extractAffectedVersions(mk("Alpine", "curl", []osvRangeEvent{{Introduced: "0"}}, nil), "Alpine", "curl"); len(got) != 1 || got[0] != "*" {
		t.Fatalf("open range = %#v, want [*]", got)
	}
	// Matched package, introduced+last_affected -> bounded group with lower bound.
	if got := extractAffectedVersions(mk("Alpine", "curl", []osvRangeEvent{{Introduced: "1.0"}, {LastAffected: "2.0"}}, nil), "Alpine", "curl"); len(got) != 1 || got[0] != ">= 1.0, <= 2.0" {
		t.Fatalf("last_affected = %#v, want [\">= 1.0, <= 2.0\"]", got)
	}
	// Matched package, explicit versions list.
	if got := extractAffectedVersions(mk("Alpine", "curl", nil, []string{"1.2.3"}), "Alpine", "curl"); len(got) != 1 || got[0] != "1.2.3" {
		t.Fatalf("versions = %#v, want [1.2.3]", got)
	}
	// Matched package, range present but no events -> fail closed (none).
	if got := extractAffectedVersions(mk("Alpine", "curl", []osvRangeEvent{}, nil), "Alpine", "curl"); len(got) != 1 || got[0] != "none" {
		t.Fatalf("eventless range = %#v, want [none]", got)
	}
}

func TestCaptureCorrelationLogger(t *testing.T) {
	log := &CaptureCorrelationLogger{}
	log.LogUnsupportedEcosystem("", "", "", "")
	log.LogMalformedPURL("", "", "", "", "malformed_purl")
	log.LogIdentityMismatch("", "", "", "", "", "")
	log.LogVersionNoMatch("", "", "", "", "")
	log.LogSkipSummary(map[string]int{"apk": 2})
	if log.Unsupported != 1 || log.Identity != 1 || log.Version != 1 || log.SummaryCounts["apk"] != 2 {
		t.Fatalf("log = %#v", log)
	}
}

func TestNoOpCorrelationLogger(t *testing.T) {
	var l NoOpCorrelationLogger
	l.LogUnsupportedEcosystem("p", "rpm", "n", "v")
	l.LogMalformedPURL("p", "apk", "n", "v", "malformed_purl")
	l.LogIdentityMismatch("p", "apk", "n", "v", "other", "CVE-1")
	l.LogVersionNoMatch("p", "apk", "n", "v", "CVE-1")
	l.LogSkipSummary(map[string]int{"rpm": 1})
}

func TestLoggerCorrelation(t *testing.T) {
	var l LoggerCorrelation // nil Log → NopLogger, no panic
	l.LogUnsupportedEcosystem("p", "apk", "n", "v")
	l.LogMalformedPURL("p", "apk", "n", "v", "malformed_purl")
	l.LogIdentityMismatch("p", "apk", "n", "v", "other", "CVE-1")
	l.LogVersionNoMatch("p", "apk", "n", "v", "CVE-1")
	l.LogSkipSummary(nil)
	l.LogSkipSummary(map[string]int{"rpm": 2})

	withLogger := LoggerCorrelation{Log: domain.NopLogger{}}
	withLogger.LogUnsupportedEcosystem("p", "apk", "n", "v")
}

func TestParseCVSSScoreAndSeverity(t *testing.T) {
	if score, vector := parseCVSSScore(""); score != 0 || vector != "" {
		t.Fatalf("empty score = %v vector = %q", score, vector)
	}
	if score, _ := parseCVSSScore("7.5"); score != 7.5 {
		t.Fatalf("numeric score = %v", score)
	}
	if score, vector := parseCVSSScore("not-a-score"); score != 0 || vector != "" {
		t.Fatalf("invalid score = %v vector = %q", score, vector)
	}
	vector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	if score, v := parseCVSSScore(vector); score < 9 || v != vector {
		t.Fatalf("vector score = %v vector = %q", score, v)
	}
	changed := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
	if score, ok := cvssV3BaseScore(changed); !ok || score <= 0 {
		t.Fatalf("changed scope score = %v ok = %v", score, ok)
	}
	for _, vector := range []string{
		"CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N",
		"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H",
		"CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
	} {
		if score, ok := cvssV3BaseScore(vector); !ok || score < 0 {
			t.Fatalf("vector %q score = %v ok = %v", vector, score, ok)
		}
	}
	if _, ok := cvssV3BaseScore("CVSS:3.1/bad"); ok {
		t.Fatal("expected invalid vector")
	}

	for _, tc := range []struct {
		score float64
		want  string
	}{
		{9.5, "critical"},
		{7.5, "high"},
		{5.0, "medium"},
		{2.0, "low"},
		{0, "unknown"},
	} {
		if got := severityFromScore(tc.score); got != tc.want {
			t.Fatalf("severityFromScore(%v) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

func TestExtractCVSSFromSeverity(t *testing.T) {
	score, vector := extractCVSSFromSeverity([]struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	}{
		{Type: "CVSS_V3", Score: "8.1"},
	})
	if score != 8.1 || vector != "" {
		t.Fatalf("score = %v vector = %q", score, vector)
	}
	score, _ = extractCVSSFromSeverity([]struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	}{
		{Type: "OTHER", Score: "6.5"},
	})
	if score != 6.5 {
		t.Fatalf("fallback score = %v", score)
	}
}

func TestNormalizePackageNameDefault(t *testing.T) {
	if got := normalizePackageName("npm", "lodash"); got != "lodash" {
		t.Fatalf("normalizePackageName() = %q", got)
	}
}

func TestComponentFetcherPaths(t *testing.T) {
	log := &CaptureCorrelationLogger{}
	fetcher := &ComponentFetcher{Logger: log}
	out, err := fetcher.FetchForComponent(context.Background(), domain.CanonicalComponent{
		PURL: "pkg:apk/busybox@1.0", Ecosystem: "apk", Name: "busybox", Version: "1.0",
	})
	if err != nil || len(out) != 0 {
		t.Fatalf("nil client out = %#v err = %v", out, err)
	}
	fetcher.EmitCorrelationSummary()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"vulns": [{
				"id": "CVE-2024-1000",
				"severity": [{"type": "CVSS_V3", "score": "7.5"}],
				"affected": [{
					"package": {"ecosystem": "Alpine", "name": "busybox"},
					"versions": ["1.0"]
				}]
			}, {
				"id": "CVE-2024-1002",
				"affected": [{
					"package": {"ecosystem": "Alpine", "name": "busybox"},
					"versions": ["9.9"]
				}]
			}]
		}`))
	}))
	t.Cleanup(srv.Close)

	client := NewClient(ClientConfig{BaseURL: srv.URL, RateLimiter: NewTokenBucket(100, 100)})
	fetcher = &ComponentFetcher{Client: client, Logger: log}
	out, err = fetcher.FetchForComponent(context.Background(), domain.CanonicalComponent{
		PURL: "pkg:apk/busybox@1.0", Ecosystem: "apk", Name: "busybox", Version: "1.0",
	})
	if err != nil {
		t.Fatalf("FetchForComponent() error = %v", err)
	}
	if len(out) != 1 || out[0].CVEID != "CVE-2024-1000" {
		t.Fatalf("out = %#v", out)
	}
	if log.Version != 1 {
		t.Fatalf("version=%d", log.Version)
	}
}

func TestClientQueryByEcosystemEdgeCases(t *testing.T) {
	client := NewClient(ClientConfig{RateLimiter: NewTokenBucket(100, 100)})
	if out, err := client.QueryByEcosystem(context.Background(), "apk", nil); err != nil || out != nil {
		t.Fatalf("empty packages = %#v err = %v", out, err)
	}
	if out, err := client.QueryByEcosystem(context.Background(), "rpm", []domain.OSVPackageQuery{{Name: "openssl"}}); err != nil || len(out) != 0 {
		t.Fatalf("unsupported ecosystem = %#v err = %v", out, err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "upstream error", http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)
	client = NewClient(ClientConfig{BaseURL: srv.URL, RateLimiter: NewTokenBucket(100, 100)})
	if _, err := client.QueryByEcosystem(context.Background(), "apk", []domain.OSVPackageQuery{{Name: "busybox"}}); err == nil {
		t.Fatal("expected api error")
	}

	srvOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulns":[{"id":"CVE-2024-2000","severity":[{"type":"CVSS_V3","score":"4.0"}],"affected":[{"package":{"ecosystem":"Alpine","name":"zlib"},"ranges":[{"events":[{"introduced":"0","fixed":"1.1"}]}]}]}]}`))
	}))
	t.Cleanup(srvOK.Close)
	client = NewClient(ClientConfig{BaseURL: srvOK.URL, RateLimiter: NewTokenBucket(100, 100)})
	out, err := client.QueryByEcosystem(context.Background(), "apk", []domain.OSVPackageQuery{{Name: "zlib"}})
	if err != nil || len(out) != 1 || out[0].CVEID != "CVE-2024-2000" {
		t.Fatalf("out = %#v err = %v", out, err)
	}

	srvEvents := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulns":[{"id":"CVE-2024-2001","affected":[{"package":{"ecosystem":"Alpine","name":"curl"},"ranges":[{"events":[{"last_affected":"1.2"}]}]}]}]}`))
	}))
	t.Cleanup(srvEvents.Close)
	client = NewClient(ClientConfig{BaseURL: srvEvents.URL, RateLimiter: NewTokenBucket(100, 100)})
	out, err = client.QueryByEcosystem(context.Background(), "apk", []domain.OSVPackageQuery{{Name: "curl"}})
	if err != nil || len(out) != 1 || len(out[0].AffectedVersions) == 0 {
		t.Fatalf("last_affected out = %#v err = %v", out, err)
	}
}

func TestEmitCorrelationSummaryWithSkips(t *testing.T) {
	log := &CaptureCorrelationLogger{}
	fetcher := &ComponentFetcher{Logger: log}
	_, _ = fetcher.FetchForComponent(context.Background(), domain.CanonicalComponent{
		PURL: "pkg:rpm/x@1", Ecosystem: "rpm", Name: "x", Version: "1",
	})
	fetcher.EmitCorrelationSummary()
	if log.SummaryCounts["rpm"] != 1 {
		t.Fatalf("summary = %#v", log.SummaryCounts)
	}
	fetcher.EmitCorrelationSummary()
}

func TestNewClientDefaults(t *testing.T) {
	client := NewClient(ClientConfig{})
	if client == nil {
		t.Fatal("expected client")
	}
}

func TestTokenBucketWaitAndSleepContext(t *testing.T) {
	tb := NewTokenBucket(0, 0)
	if tb.rate <= 0 || tb.capacity <= 0 {
		t.Fatalf("defaults not applied: rate=%v capacity=%v", tb.rate, tb.capacity)
	}

	tb = NewTokenBucket(1000, 1)
	tb.tokens = 0
	tb.sleep = func(context.Context, time.Duration) error { return nil }
	if err := tb.Wait(context.Background()); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepContext(ctx, time.Second); err == nil {
		t.Fatal("expected cancelled context error")
	}
}
