package watch

import (
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

func TestMergeFeedVulnerabilitiesDedupes(t *testing.T) {
	first := []domain.FeedVulnerability{{CVEID: "CVE-1", Ecosystem: "npm", PackageName: "lodash"}}
	second := []domain.FeedVulnerability{{CVEID: "CVE-1", Ecosystem: "npm", PackageName: "lodash"}, {CVEID: "CVE-2", Ecosystem: "npm", PackageName: "lodash"}}
	merged := mergeFeedVulnerabilities(first, second)
	if len(merged) != 2 {
		t.Fatalf("len(merged) = %d, want 2", len(merged))
	}
}

// TestMergeFeedVulnerabilitiesKeepsHigherPrecedence covers the CR-3 merge: on a
// key collision the higher-precedence source wins regardless of iteration order.
func TestMergeFeedVulnerabilitiesKeepsHigherPrecedence(t *testing.T) {
	nvd := []domain.FeedVulnerability{{CVEID: "CVE-1", Ecosystem: "npm", PackageName: "lodash", Source: domain.FindingSourceNVD}}
	osv := []domain.FeedVulnerability{{CVEID: "CVE-1", Ecosystem: "npm", PackageName: "lodash", Source: domain.FindingSourceOSV}}

	// NVD seen first, then OSV (higher) replaces it.
	merged := mergeFeedVulnerabilities(nvd, osv)
	if len(merged) != 1 || merged[0].Source != domain.FindingSourceOSV {
		t.Fatalf("expected osv to win, got %+v", merged)
	}

	// OSV seen first, then NVD (lower) does NOT replace it.
	merged = mergeFeedVulnerabilities(osv, nvd)
	if len(merged) != 1 || merged[0].Source != domain.FindingSourceOSV {
		t.Fatalf("expected osv to remain, got %+v", merged)
	}
}

func TestFirstFixVersion(t *testing.T) {
	if got := firstFixVersion(nil); got != "" {
		t.Fatalf("empty = %q", got)
	}
	if got := firstFixVersion([]string{"1.2.3", "2.0.0"}); got != "1.2.3" {
		t.Fatalf("first = %q", got)
	}
}

func TestRecordsToFeedPreservesIdentity(t *testing.T) {
	out := recordsToFeed([]domain.VulnerabilityRecord{{
		CVEID: "CVE-1", Ecosystem: "npm", PackageName: "lodash", AffectedVersions: []string{"< 4.18.0"},
	}})
	if len(out) != 1 || out[0].PackageName != "lodash" {
		t.Fatalf("recordsToFeed() = %+v", out)
	}
}
