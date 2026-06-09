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

func TestRecordsToFeedPreservesIdentity(t *testing.T) {
	out := recordsToFeed([]domain.VulnerabilityRecord{{
		CVEID: "CVE-1", Ecosystem: "npm", PackageName: "lodash", AffectedVersions: []string{"< 4.18.0"},
	}})
	if len(out) != 1 || out[0].PackageName != "lodash" {
		t.Fatalf("recordsToFeed() = %+v", out)
	}
}
