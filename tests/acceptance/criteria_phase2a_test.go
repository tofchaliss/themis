//go:build integration

package acceptance_test

import (
	"os/exec"
	"strings"
	"testing"
)

func TestPhase2aAcceptanceCriteriaCoverage(t *testing.T) {
	mappings := []struct {
		id    int
		desc  string
		tests []string
	}{
		{16, "KEV retroactive score increase", []string{"TestAC16_KEVRetroactiveScoreIncrease", "TestReEnrichJob_BatchCap1200", "TestReEnrichJob_Idempotent"}},
		{17, "Alpine vendor VEX not_affected", []string{"TestAC17_AlpineVendorVEXNotAffected"}},
		{18, "RPM namespace alias vendor VEX", []string{"TestAC18_RPMNamespaceAlias"}},
		{19, "Backport authority httpd VEX", []string{"TestAC19_HttpdBackportAuthority"}},
		{20, "Layer 1/2 synchronous enrichment", []string{"TestAC20_Layer1SynchronousBeforeAccepted", "TestAC20_Layer2SynchronousBeforeAccepted"}},
		{21, "Blast-radius cap and dedup", []string{"TestAC21_BlastRadiusCap", "TestAC21_BlastRadiusCustomerDedup"}},
		{22, "Soft-delete data isolation", []string{"TestAC22_SoftDeleteIsolation"}},
		{23, "Error catalogue envelope", []string{"TestAC23_NoRawDBErrorLeaks", "TestErrorCode_InternalError"}},
		{24, "VEX export CycloneDX and precedence", []string{"TestAC24_VEXExportPrecedence"}},
	}

	root := moduleRoot(t)
	listCmd := exec.Command("go", "list", "-tags=integration", "./internal/...", "./tests/...")
	listCmd.Dir = root
	pkgOut, err := listCmd.Output()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, pkgOut)
	}
	pkgs := strings.Fields(strings.TrimSpace(string(pkgOut)))
	args := append([]string{"test", "-tags=integration", "-list", "."}, pkgs...)
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go test -list: %v\n%s", err, out)
	}
	listing := string(out)

	for _, mapping := range mappings {
		mapping := mapping
		t.Run(mapping.desc, func(t *testing.T) {
			for _, name := range mapping.tests {
				if !strings.Contains(listing, name) {
					t.Fatalf("AC-%d missing test %q", mapping.id, name)
				}
			}
		})
	}
}

func TestPhase2aFeedResilienceCoverage(t *testing.T) {
	tests := []string{
		"TestClientHTTP500Retries",
		"TestServiceRunSyncAbortsTruncatedEPSS",
		"TestClientFetchKEV",
		"TestServiceEmptyCSVPreservesExisting",
		"TestVendorFeed_HTTP429_Retry",
		"TestVendorFeed_MalformedCSAF",
		"TestParseEPSSCSVRejectsOutOfRange",
		"TestFeedResilience_StaleFlag",
	}
	root := moduleRoot(t)
	cmd := exec.Command("go", "test", "-tags=integration", "-list", ".", "./internal/...")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go test -list: %v\n%s", err, out)
	}
	listing := string(out)
	for _, name := range tests {
		if !strings.Contains(listing, name) {
			t.Fatalf("missing feed resilience test %q", name)
		}
	}
}
