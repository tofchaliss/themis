package parser

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/domain"
)

func TestCycloneDXAdapterVersions(t *testing.T) {
	base := cycloneDXFixture(t)
	for _, version := range []string{"1.4", "1.5", "1.6"} {
		doc := cloneMap(base)
		doc["specVersion"] = version
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		sbom, err := (CycloneDXAdapter{}).Parse(context.Background(), raw, version)
		if err != nil {
			t.Fatalf("Parse(%s): %v", version, err)
		}
		if len(sbom.Components) != 1 {
			t.Fatalf("components = %d, want 1", len(sbom.Components))
		}
	}
}

func TestCycloneDXAdapterMissingPURLAndMalformed(t *testing.T) {
	raw := []byte(`{
		"bomFormat":"CycloneDX","specVersion":"1.4",
		"components":[
			{"name":"no-purl","version":"1.0.0"},
			{"name":"bad-purl","version":"1.0.0","purl":"not-purl"},
			{"name":"good","version":"2.0.0","purl":"pkg:npm/good@2.0.0"}
		]
	}`)
	sbom, err := (CycloneDXAdapter{}).Parse(context.Background(), raw, "1.4")
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Components) != 1 {
		t.Fatalf("components = %d, want 1", len(sbom.Components))
	}
	if len(sbom.Warnings) != 2 {
		t.Fatalf("warnings = %d, want 2", len(sbom.Warnings))
	}
}

func TestCycloneDXAdapterDependencies(t *testing.T) {
	raw := []byte(`{
		"bomFormat":"CycloneDX","specVersion":"1.5",
		"components":[{"name":"a","version":"1","purl":"pkg:npm/a@1"}],
		"dependencies":[{"ref":"pkg:npm/a@1","dependsOn":["pkg:npm/b@2"]}]
	}`)
	sbom, err := (CycloneDXAdapter{}).Parse(context.Background(), raw, "1.5")
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Dependencies) != 1 || sbom.Dependencies[0].RelationshipType != "depends_on" {
		t.Fatalf("dependencies = %+v", sbom.Dependencies)
	}
	if sbom.Dependencies[0].FromPURL != "pkg:npm/a@1" || sbom.Dependencies[0].ToPURL != "pkg:npm/b@2" {
		t.Fatalf("edge = %+v", sbom.Dependencies[0])
	}
}

// TestCycloneDXAdapterBomRefDependencies locks in the CR-9 fix: dependency edges
// reference bom-refs that are not purls; they must resolve to component purls.
func TestCycloneDXAdapterBomRefDependencies(t *testing.T) {
	raw := []byte(`{
		"bomFormat":"CycloneDX","specVersion":"1.5",
		"components":[
			{"bom-ref":"ref-a","name":"a","version":"1","purl":"pkg:npm/a@1"},
			{"bom-ref":"ref-b","name":"b","version":"2","purl":"pkg:npm/b@2"}
		],
		"dependencies":[{"ref":"ref-a","dependsOn":["ref-b","ref-unknown"]}]
	}`)
	sbom, err := (CycloneDXAdapter{}).Parse(context.Background(), raw, "1.5")
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Dependencies) != 1 {
		t.Fatalf("want 1 resolvable edge, got %+v", sbom.Dependencies)
	}
	edge := sbom.Dependencies[0]
	if edge.FromPURL != "pkg:npm/a@1" || edge.ToPURL != "pkg:npm/b@2" {
		t.Fatalf("bom-ref not resolved to purl: %+v", edge)
	}
}

// TestCycloneDXAdapterSkipsUnresolvableDependencyFrom exercises the path where a
// dependency's from-ref resolves to nothing (unknown, non-purl bom-ref): no edge.
func TestCycloneDXAdapterSkipsUnresolvableDependencyFrom(t *testing.T) {
	raw := []byte(`{
		"bomFormat":"CycloneDX","specVersion":"1.5",
		"components":[{"bom-ref":"ref-b","name":"b","version":"2","purl":"pkg:npm/b@2"}],
		"dependencies":[{"ref":"unknown-ref","dependsOn":["ref-b"]}]
	}`)
	sbom, err := (CycloneDXAdapter{}).Parse(context.Background(), raw, "1.5")
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Dependencies) != 0 {
		t.Fatalf("want 0 edges (unresolvable from), got %+v", sbom.Dependencies)
	}
}

func TestCycloneDXAdapterErrors(t *testing.T) {
	_, err := (CycloneDXAdapter{}).Parse(context.Background(), []byte("{"), "1.4")
	if err == nil {
		t.Fatal("expected malformed json error")
	}
	_, err = (CycloneDXAdapter{}).Parse(context.Background(), []byte(`{"bomFormat":"Other","specVersion":"1.4"}`), "1.4")
	if err == nil || !strings.Contains(err.Error(), "bomFormat") {
		t.Fatalf("expected bomFormat error, got %v", err)
	}
	_, err = (CycloneDXAdapter{}).Parse(context.Background(), []byte(`{"bomFormat":"CycloneDX","specVersion":"9.9"}`), "9.9")
	if err == nil {
		t.Fatal("expected unsupported version error")
	}
}

func TestCycloneDXAdapterUsesDocumentSpecVersion(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","purl":"pkg:npm/a@1"}]}`)
	sbom, err := (CycloneDXAdapter{}).Parse(context.Background(), raw, "")
	if err != nil {
		t.Fatal(err)
	}
	if sbom.SpecVersion != "1.6" {
		t.Fatalf("SpecVersion = %q", sbom.SpecVersion)
	}
}

func TestCycloneDXAdapterDerivesNameVersionFromPURL(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","components":[{"purl":"pkg:npm/derived@9.9.9"}]}`)
	sbom, err := (CycloneDXAdapter{}).Parse(context.Background(), raw, "1.4")
	if err != nil {
		t.Fatal(err)
	}
	if sbom.Components[0].Name != "derived" || sbom.Components[0].Version != "9.9.9" {
		t.Fatalf("component = %+v", sbom.Components[0])
	}
}

// TestCycloneDXAdapterIgnoresEmbeddedVulnerabilities confirms the CR-9 decision:
// a CycloneDX document's embedded vulnerabilities section is not ingested (Themis
// re-correlates), so it produces no findings and does not error.
func TestCycloneDXAdapterIgnoresEmbeddedVulnerabilities(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","components":[{"name":"a","version":"1","purl":"pkg:npm/a@1"}],"vulnerabilities":[{"id":"CVE-2","ratings":[{"severity":"low","score":1}],"affects":[{"ref":"pkg:npm/a@1"}]}]}`)
	sbom, err := (CycloneDXAdapter{}).Parse(context.Background(), raw, "1.4")
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Components) != 1 {
		t.Fatalf("components = %d", len(sbom.Components))
	}
}

// TestCycloneDXAdapterGoldenRockyMixed is the golden-corpus regression for a real
// Trivy Rocky-8 CycloneDX SBOM. It locks the parser's handling of the awkward
// shapes that file exercises: mixed UUID/purl bom-refs, percent-encoded rpm names,
// epoch-prefixed and modular RPM versions, duplicate purls across bom-refs, a
// no-purl operating-system component, and an empty embedded vulnerabilities array.
func TestCycloneDXAdapterGoldenRockyMixed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "trivy-rocky-mixed.cyclonedx.json"))
	if err != nil {
		t.Fatal(err)
	}
	sbom, err := (CycloneDXAdapter{}).Parse(context.Background(), raw, "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// 11 components in the file; the no-purl operating-system one is skipped.
	if len(sbom.Components) != 10 {
		t.Fatalf("components = %d, want 10", len(sbom.Components))
	}
	sawOSWarning := false
	for _, w := range sbom.Warnings {
		if strings.Contains(w, "rocky") {
			sawOSWarning = true
		}
	}
	if !sawOSWarning {
		t.Fatalf("expected a skip warning for the no-purl OS component; warnings=%v", sbom.Warnings)
	}

	byName := map[string]domain.CanonicalComponent{}
	names := make([]string, 0, len(sbom.Components))
	purlCounts := map[string]int{}
	ecosystems := map[string]int{}
	for _, c := range sbom.Components {
		byName[c.Name] = c
		names = append(names, c.Name)
		purlCounts[c.PURL]++
		ecosystems[c.Ecosystem]++
	}

	// libstdc++ keeps its decoded name from the JSON field (not the %2B%2B purl).
	if byName["libstdc++"].Ecosystem != "rpm" {
		t.Fatalf("libstdc++ missing/wrong ecosystem: %+v", byName["libstdc++"])
	}
	// device-mapper-libs keeps the epoch-prefixed NEVRA for rpm comparison.
	if got := byName["device-mapper-libs"].Version; got != "8:1.02.181-15.el8_10.3" {
		t.Fatalf("device-mapper-libs version = %q", got)
	}
	// httpd modular version survives intact.
	if got := byName["httpd"].Version; got != "2.4.37-65.module+el8.10.0+40053+5a18018e.7" {
		t.Fatalf("httpd version = %q", got)
	}
	// The component with no name/version falls back to the purl, percent-decoded
	// ("%2B"→"+"). The namespace is retained here and stripped later by the distro
	// correlation source; what matters is that the encoding is resolved.
	if _, ok := byName["rocky/perl-Text-Tabs+Wrap"]; !ok {
		t.Fatalf("perl-Text-Tabs+Wrap not derived/decoded from purl; names=%v", names)
	}
	// Duplicate purl across two bom-refs is preserved (deduped later at identity).
	if purlCounts["pkg:maven/org.springframework/spring-beans@6.2.11"] != 2 {
		t.Fatalf("expected spring-beans purl twice, got %d", purlCounts["pkg:maven/org.springframework/spring-beans@6.2.11"])
	}
	if ecosystems["rpm"] == 0 || ecosystems["pypi"] == 0 || ecosystems["maven"] == 0 {
		t.Fatalf("missing expected ecosystems: %v", ecosystems)
	}

	// Dependency edges resolve both a UUID bom-ref ("u-spring-1") and a purl
	// bom-ref to purls.
	var sawUUIDResolved, sawPurlResolved bool
	for _, e := range sbom.Dependencies {
		switch e.ToPURL {
		case "pkg:maven/org.springframework/spring-beans@6.2.11":
			sawUUIDResolved = true
		case "pkg:maven/com.example/kafka@0.1.0":
			sawPurlResolved = true
		}
	}
	if !sawUUIDResolved || !sawPurlResolved {
		t.Fatalf("dependency refs not resolved (uuid=%v purl=%v): %+v", sawUUIDResolved, sawPurlResolved, sbom.Dependencies)
	}
}

func cycloneDXFixture(t *testing.T) map[string]any {
	t.Helper()
	return map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.4",
		"components": []map[string]any{
			{"name": "lodash", "version": "1.0.0", "purl": "pkg:npm/lodash@1.0.0"},
		},
	}
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func TestParseFixtureFiles(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	cycloneRaw, err := os.ReadFile(filepath.Join("testdata", "cyclonedx-1.6.json"))
	if err != nil {
		t.Fatal(err)
	}
	outcome := registry.Parse(context.Background(), domain.SBOMFormatCycloneDX, "1.6", cycloneRaw)
	if !outcome.Accepted {
		t.Fatalf("cyclonedx parse failed: %s", outcome.Message)
	}
	counts := InspectCanonicalSBOM(outcome.SBOM)
	if counts["components"] != 2 || counts["dependencies"] != 1 {
		t.Fatalf("cyclonedx counts = %+v", counts)
	}

	spdxRaw, err := os.ReadFile(filepath.Join("testdata", "spdx-2.3.json"))
	if err != nil {
		t.Fatal(err)
	}
	outcome = registry.Parse(context.Background(), domain.SBOMFormatSPDX, "2.3", spdxRaw)
	if !outcome.Accepted {
		t.Fatalf("spdx parse failed: %s", outcome.Message)
	}
	counts = InspectCanonicalSBOM(outcome.SBOM)
	if counts["components"] != 2 || counts["dependencies"] != 1 {
		t.Fatalf("spdx counts = %+v", counts)
	}
}

func TestRunAdapterParseContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	_, err := runAdapterParse(ctx, slowParseAdapter{}, nil, "")
	if err == nil {
		t.Fatal("expected context error")
	}
}

type slowParseAdapter struct{}

func (slowParseAdapter) Format() string { return "slow" }

func (slowParseAdapter) Parse(ctx context.Context, _ []byte, _ string) (domain.CanonicalSBOM, error) {
	select {
	case <-ctx.Done():
		return domain.CanonicalSBOM{}, ctx.Err()
	case <-time.After(time.Second):
		return domain.CanonicalSBOM{}, nil
	}
}

func TestRegistryUnknownFormat(t *testing.T) {
	outcome := NewRegistry(RegistryConfig{}).Parse(context.Background(), "unknown", "", []byte("{}"))
	if outcome.Accepted || outcome.HTTPStatus != 422 {
		t.Fatalf("outcome = %+v", outcome)
	}
	if len(outcome.SupportedFormats) != 4 {
		t.Fatalf("supported formats = %v", outcome.SupportedFormats)
	}
}

func TestRegistryComponentLimit(t *testing.T) {
	components := make([]map[string]string, 3)
	for i := range components {
		components[i] = map[string]string{
			"name":    "c",
			"version": "1",
			"purl":    "pkg:npm/c@1",
		}
	}
	raw, err := json.Marshal(map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.4", "components": components,
	})
	if err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry(RegistryConfig{MaxComponents: 2, ParseTimeout: time.Second})
	outcome := registry.Parse(context.Background(), domain.SBOMFormatCycloneDX, "1.4", raw)
	if outcome.Accepted || outcome.Status != domain.ParseStatusRejected {
		t.Fatalf("outcome = %+v", outcome)
	}
	if !strings.Contains(outcome.Message, "component count") {
		t.Fatalf("message = %q", outcome.Message)
	}
}

func TestRegistryParseTimeout(t *testing.T) {
	original := runAdapterParse
	runAdapterParse = func(ctx context.Context, adapter domain.SBOMAdapter, raw []byte, specVersion string) (domain.CanonicalSBOM, error) {
		timer := time.NewTimer(50 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return domain.CanonicalSBOM{}, ctx.Err()
		case <-timer.C:
			return adapter.Parse(ctx, raw, specVersion)
		}
	}
	t.Cleanup(func() { runAdapterParse = original })

	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","components":[{"purl":"pkg:npm/a@1"}]}`)
	registry := NewRegistry(RegistryConfig{ParseTimeout: time.Millisecond})
	outcome := registry.Parse(context.Background(), domain.SBOMFormatCycloneDX, "1.4", raw)
	if outcome.Accepted || outcome.Status != domain.ParseStatusFailed {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestRegistryParseDeadlineExceededError(t *testing.T) {
	original := runAdapterParse
	runAdapterParse = func(context.Context, domain.SBOMAdapter, []byte, string) (domain.CanonicalSBOM, error) {
		return domain.CanonicalSBOM{}, context.DeadlineExceeded
	}
	t.Cleanup(func() { runAdapterParse = original })

	outcome := NewRegistry(RegistryConfig{}).Parse(context.Background(), domain.SBOMFormatCycloneDX, "1.4", []byte("{}"))
	if outcome.Status != domain.ParseStatusFailed || outcome.HTTPStatus != 408 {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestRegistrySetsSpecVersionFromRequest(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	registry.adapters[domain.SBOMFormatCycloneDX] = emptySpecVersionAdapter{}
	outcome := registry.Parse(context.Background(), domain.SBOMFormatCycloneDX, "1.4", []byte("{}"))
	if !outcome.Accepted || outcome.SBOM.SpecVersion != "1.4" {
		t.Fatalf("outcome = %+v", outcome)
	}
}

type emptySpecVersionAdapter struct{}

func (emptySpecVersionAdapter) Format() string { return domain.SBOMFormatCycloneDX }

func (emptySpecVersionAdapter) Parse(context.Context, []byte, string) (domain.CanonicalSBOM, error) {
	return domain.CanonicalSBOM{}, nil
}

func TestRegistryAdapterParseError(t *testing.T) {
	outcome := NewRegistry(RegistryConfig{}).Parse(context.Background(), domain.SBOMFormatCycloneDX, "1.4", []byte("{"))
	if outcome.Accepted || outcome.Status != domain.ParseStatusRejected {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestRegistryDefaultConfig(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	if registry.config.MaxComponents != defaultMaxComponents {
		t.Fatalf("MaxComponents = %d", registry.config.MaxComponents)
	}
	if registry.config.ParseTimeout != defaultParseTimeout {
		t.Fatalf("ParseTimeout = %s", registry.config.ParseTimeout)
	}
}

func TestRegistrySuccessfulParseSetsFormat(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","components":[{"purl":"pkg:npm/a@1"}]}`)
	outcome := NewRegistry(RegistryConfig{}).Parse(context.Background(), domain.SBOMFormatCycloneDX, "", raw)
	if !outcome.Accepted || outcome.SBOM.Format != domain.SBOMFormatCycloneDX {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestStringsJoinEmpty(t *testing.T) {
	if stringsJoin(nil) != "" {
		t.Fatal("expected empty string")
	}
}

func TestAdapterFormats(t *testing.T) {
	if (CycloneDXAdapter{}).Format() != domain.SBOMFormatCycloneDX {
		t.Fatal("cyclonedx format mismatch")
	}
	if (SPDXAdapter{}).Format() != domain.SBOMFormatSPDX {
		t.Fatal("spdx format mismatch")
	}
	if (TrivyAdapter{}).Format() != domain.SBOMFormatTrivy {
		t.Fatal("trivy format mismatch")
	}
}

func TestInspectCanonicalSBOMReadsAllFields(t *testing.T) {
	counts := InspectCanonicalSBOM(domain.CanonicalSBOM{
		Format: "cyclonedx", SpecVersion: "1.4",
		Components:   []domain.CanonicalComponent{{PURL: "pkg:npm/a@1", Name: "a", Version: "1", Ecosystem: "npm", Licenses: []string{"MIT"}}},
		Dependencies: []domain.CanonicalDependencyEdge{{FromPURL: "a", ToPURL: "b", RelationshipType: "depends_on"}},
		Warnings:     []string{"warn"},
	})
	if counts["components"] != 1 {
		t.Fatalf("counts = %+v", counts)
	}
}
