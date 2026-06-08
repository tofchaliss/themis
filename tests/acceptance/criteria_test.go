//go:build integration

package acceptance_test

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func moduleRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatalf("go env GOMOD: %v", err)
	}
	modFile := strings.TrimSpace(string(out))
	if modFile == "" || modFile == "/dev/null" {
		t.Fatal("module root not found")
	}
	return filepath.Dir(modFile)
}

func TestAcceptanceCriteriaCoverage(t *testing.T) {
	mappings := []struct {
		id    int
		desc  string
		tests []string
	}{
		{1, "CI webhook POST triggers ingestion", []string{"TestWebhookAccepted", "TestAPIFlowIntegrationPostgres"}},
		{2, "SBOM parse and normalize via adapters", []string{"TestRegistryDefaultConfig", "TestIngestionPipelineIntegrationPostgres"}},
		{3, "Manual upload API same pipeline as webhook", []string{"TestE2E_SBOMPipelineDetected", "TestUploadSBOMAccepted"}},
		{4, "Artifact validation gate records trust", []string{"TestGateIntegrationPostgres", "TestGateAcceptsSignedSBOMUnderStandardPolicy"}},
		{5, "CVE correlation stores immutable findings", []string{"TestIngestionPipelineIntegrationPostgres", "TestE2E_SBOMPipelineDetected"}},
		{6, "VEX L3 suppression preserves raw finding", []string{"TestEnrichmentVEXOverlayIntegrationPostgres", "TestE2E_VEXSuppressionPreservesFinding"}},
		{7, "L4 triage generates VEX for future ingestions", []string{"TestTriageFlowIntegrationPostgres", "TestE2E_TriageGeneratedVEXAutoApply"}},
		{8, "Background CVE watch creates findings", []string{"TestWatchCycleIntegrationPostgres", "TestE2EWatchCycleWithSMTPIntegrationPostgres"}},
		{9, "Continuous enrichment updates risk context", []string{"TestApplyVEXCreatesDetectedRiskContext", "TestEnrichmentVEXOverlayIntegrationPostgres"}},
		{10, "Notifications on ingest/triage/watch", []string{"TestNotificationServiceIntegration", "TestE2EWatchCycleWithSMTPIntegrationPostgres"}},
		{11, "Multi product/project isolation", []string{"TestListProductsAndConfig", "TestAPIFlowIntegrationPostgres"}},
		{12, "Config-driven parser registry", []string{"TestRegistryDefaultConfig", "TestRegistryPort"}},
		{13, "Immutable raw evidence layers", []string{"TestE2E_VEXRevokeResurface", "TestEnrichmentVEXOverlayIntegrationPostgres"}},
		{14, "Duplicate SBOM idempotent ingestion", []string{"TestE2E_DuplicateSBOMIdempotency", "TestIngestionPipelineIntegrationPostgres"}},
		{15, "Integrity chain VEX→SBOM→image", []string{"TestGateIntegrationPostgres", "TestGateVEXIntegrityChain"}},
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
			if len(mapping.tests) == 0 {
				t.Fatalf("criterion %d has no mapped tests", mapping.id)
			}
			for _, name := range mapping.tests {
				if !strings.Contains(listing, name) {
					t.Fatalf("criterion %d missing test %q", mapping.id, name)
				}
			}
		})
	}
}
