package feed_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/adapters/feed"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// TestFeedsSeamE2E wires the real feed clients + ACLs through translation → reconciliation
// the way the pipeline does: OSV discovers a CVE for a component, the NVD client resolves a
// CVSS-4.0-only CVE into a real severity (D-NVD-2), a scanner report folds with no special
// authority (D6), and every feed is tier-classified (D-FEED-2). One flow, real HTTP.
func TestFeedsSeamE2E(t *testing.T) {
	hourAgo := time.Now().Add(-time.Hour)

	// 1) OSV discovers a CVE for a PyPI component (real query-by-package client).
	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"vulns": []json.RawMessage{json.RawMessage(
			`{"id":"CVE-2024-7000","modified":"2026-01-02T00:00:00Z","database_specific":{"severity":"HIGH","cvss_score":7.5}}`)}})
	}))
	defer osvSrv.Close()
	osvProps, err := feed.NewOSVClient(osvSrv.URL, osvSrv.Client()).
		VulnsForPackage(context.Background(), app.InventoryComponent{PURL: "pkg:pypi/urllib3@1.26.20"})
	if err != nil || len(osvProps) != 1 || osvProps[0].CVE.String() != "CVE-2024-7000" {
		t.Fatalf("osv discover = %d, %v", len(osvProps), err)
	}

	// 2) NVD resolves a CVSS-4.0-only CVE (D-NVD-2) — the folded card gets a real severity.
	nvdSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2025-8869",` +
			`"lastModified":"2026-07-20T10:00:00.000","metrics":{"cvssMetricV40":[{"type":"Secondary",` +
			`"cvssData":{"baseScore":5.9,"baseSeverity":"MEDIUM","vectorString":"CVSS:4.0/AV:N"}}]}}}]}`))
	}))
	defer nvdSrv.Close()
	nvdProps, err := feed.NewNVDClient(nvdSrv.URL, "", nvdSrv.Client()).ChangedSince(context.Background(), hourAgo)
	if err != nil || len(nvdProps) != 1 {
		t.Fatalf("nvd changed = %d, %v", len(nvdProps), err)
	}
	card, _ := domain.NewFaultline(domain.FaultlineID("fl-8869"), nvdProps[0].CVE)
	card.FoldProposal(nvdProps[0].Proposal, domain.NewPrecedence("nvd"))
	if card.View().Severity != value.SeverityMedium {
		t.Errorf("v4.0-only card severity = %v, want medium (D-NVD-2 seam e2e)", card.View().Severity)
	}

	// 3) A scanner report folds as advisory + loses the headline to the distro (no authority).
	scanOut, err := feed.NewRegistry().Translate("scanner",
		[]byte(`{"cve":"CVE-2024-8000","observed_at":"2026-07-22T00:00:00Z","severity":"critical","cvss_score":9.9}`))
	if err != nil || len(scanOut) != 1 {
		t.Fatalf("scanner translate = %d, %v", len(scanOut), err)
	}
	rockyCVSS, _ := value.NewCVSS(8.0, "")
	rocky, _ := domain.NewVulnFactsProposal("rocky", hourAgo, domain.VulnFacts{Severity: value.SeverityHigh, CVSS: rockyCVSS})
	card2, _ := domain.NewFaultline(domain.FaultlineID("fl-8000"), scanOut[0].CVE)
	card2.FoldProposal(scanOut[0].Proposal, domain.NewPrecedence("rocky"))
	card2.FoldProposal(rocky, domain.NewPrecedence("rocky"))
	if card2.View().SeveritySource != "rocky" {
		t.Errorf("headline source = %q, want rocky (scanner carries no authority)", card2.View().SeveritySource)
	}

	// 4) Every feed is tier-classified (D-FEED-2).
	r := feed.NewRegistry()
	if r.Tier("nvd") != domain.Tier1Critical || r.Tier("osv") != domain.Tier2Recommended ||
		r.Tier("scanner") != domain.Tier1Critical || r.Tier("vexfeed") != domain.Tier3Enrichment {
		t.Error("feed tier classification wrong")
	}
}
