package parser_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/themis-project/themis/internal/evidence/adapters/parser"
)

func load(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return raw
}

func componentByEcosystemName(res parser.Result) map[string]string {
	m := map[string]string{}
	for _, c := range res.Inventory.Components() {
		m[c.PURL.String()] = c.Name + "@" + c.Version
	}
	return m
}

func TestParse_CycloneDX_Golden(t *testing.T) {
	res, err := parser.NewRegistry().Parse(context.Background(), "cyclonedx", "", load(t, "cyclonedx.json"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	comps := res.Inventory.Components()
	if len(comps) != 2 {
		t.Fatalf("components = %d, want 2 (%+v)", len(comps), comps)
	}
	byPURL := componentByEcosystemName(res)
	if byPURL["pkg:deb/debian/app@1.0.0"] != "app@1.0.0" {
		t.Errorf("app component = %q", byPURL["pkg:deb/debian/app@1.0.0"])
	}
	// openssl has no name/version in the doc; both are derived from the purl.
	if byPURL["pkg:deb/debian/openssl@3.0.11"] != "debian/openssl@3.0.11" {
		t.Errorf("openssl fallback = %q", byPURL["pkg:deb/debian/openssl@3.0.11"])
	}
	// no-purl-lib and bad-purl are skipped with warnings.
	if len(res.Warnings) != 2 {
		t.Errorf("warnings = %d, want 2 (%v)", len(res.Warnings), res.Warnings)
	}
	// edges: app->openssl (via bom-ref) and app->zlib (via raw-purl fallback);
	// ref-missing is unresolved and dropped.
	if got := len(res.Inventory.Dependencies()); got != 2 {
		t.Errorf("edges = %d, want 2 (%+v)", got, res.Inventory.Dependencies())
	}
}

func TestParse_SPDX_Golden(t *testing.T) {
	res, err := parser.NewRegistry().Parse(context.Background(), "spdx", "", load(t, "spdx.json"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := len(res.Inventory.Components()); got != 2 {
		t.Fatalf("components = %d, want 2", got)
	}
	if len(res.Warnings) != 1 { // nopurl skipped
		t.Errorf("warnings = %d, want 1 (%v)", len(res.Warnings), res.Warnings)
	}
	// Only the DEPENDS_ON with both ids known becomes an edge; missing + CONTAINS drop.
	if got := len(res.Inventory.Dependencies()); got != 1 {
		t.Errorf("edges = %d, want 1", got)
	}
}

func TestParse_UnsupportedFormat(t *testing.T) {
	_, err := parser.NewRegistry().Parse(context.Background(), "trivy", "", []byte(`{}`))
	var ufe *parser.UnsupportedFormatError
	if !errors.As(err, &ufe) {
		t.Fatalf("err = %v, want *UnsupportedFormatError", err)
	}
	if ufe.Requested != "trivy" {
		t.Errorf("Requested = %q", ufe.Requested)
	}
	if msg := ufe.Error(); msg == "" || !contains(msg, "cyclonedx") || !contains(msg, "spdx") {
		t.Errorf("Error() = %q", msg)
	}
}

func TestParse_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := parser.NewRegistry().Parse(ctx, "cyclonedx", "", []byte(`{}`)); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestParse_MaxComponents(t *testing.T) {
	r := parser.NewRegistry(parser.WithMaxComponents(1))
	_, err := r.Parse(context.Background(), "cyclonedx", "", load(t, "cyclonedx.json"))
	if err == nil || !contains(err.Error(), "exceeds maximum") {
		t.Errorf("err = %v, want exceeds-maximum", err)
	}
}

func TestSupported(t *testing.T) {
	got := parser.NewRegistry().Supported()
	if len(got) != 2 || got[0] != parser.FormatCycloneDX || got[1] != parser.FormatSPDX {
		t.Errorf("Supported = %v", got)
	}
}

func TestParse_CycloneDX_Errors(t *testing.T) {
	r := parser.NewRegistry()
	ctx := context.Background()
	if _, err := r.Parse(ctx, "cyclonedx", "", []byte(`{not json`)); err == nil {
		t.Error("invalid json: want error")
	}
	if _, err := r.Parse(ctx, "cyclonedx", "", []byte(`{"bomFormat":"SPDX"}`)); err == nil {
		t.Error("bad bomFormat: want error")
	}
	if _, err := r.Parse(ctx, "cyclonedx", "9.9", []byte(`{}`)); err == nil {
		t.Error("bad version: want error")
	}
	// specVersion parameter path + a valid component without a bom-ref + an
	// unreadable-purl-type component (skipped).
	doc := `{"components":[
		{"name":"curl","version":"8.0","purl":"pkg:deb/debian/curl@8.0"},
		{"name":"weird","purl":"pkg:/weird@1"}],
		"dependencies":[{"ref":"ghost","dependsOn":["pkg:deb/debian/curl@8.0"]}]}`
	res, err := r.Parse(ctx, "cyclonedx", "1.6", []byte(doc))
	if err != nil {
		t.Fatalf("valid doc: %v", err)
	}
	if len(res.Inventory.Components()) != 1 || len(res.Warnings) != 1 {
		t.Errorf("components=%d warnings=%d, want 1/1", len(res.Inventory.Components()), len(res.Warnings))
	}
}

func TestParse_SPDX_Errors(t *testing.T) {
	r := parser.NewRegistry()
	ctx := context.Background()
	if _, err := r.Parse(ctx, "spdx", "", []byte(`{not json`)); err == nil {
		t.Error("invalid json: want error")
	}
	if _, err := r.Parse(ctx, "spdx", "9.9", []byte(`{}`)); err == nil {
		t.Error("bad version: want error")
	}
	// specVersion param; a non-package-manager ref (skipped in ref scan); a
	// PACKAGE-MANAGER/type=purl ref whose locator lacks pkg: (invalid → skipped);
	// an unreadable-type purl (skipped); SPDX-2.2 normalize is exercised elsewhere.
	doc := `{"spdxVersion":"SPDX-2.3","packages":[
		{"SPDXID":"a","name":"a","versionInfo":"1","externalRefs":[
			{"referenceCategory":"SECURITY","referenceType":"cpe23Type","referenceLocator":"cpe:/x"},
			{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:deb/debian/a@1"}]},
		{"SPDXID":"b","name":"b","externalRefs":[
			{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"maven:g:a:1"}]},
		{"SPDXID":"c","name":"c","externalRefs":[
			{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:/weird"}]}]}`
	res, err := r.Parse(ctx, "spdx", "2.3", []byte(doc))
	if err != nil {
		t.Fatalf("valid doc: %v", err)
	}
	if len(res.Inventory.Components()) != 1 { // only package "a" is usable
		t.Errorf("components = %d, want 1", len(res.Inventory.Components()))
	}
	if len(res.Warnings) != 2 { // b (invalid purl) + c (unreadable type)
		t.Errorf("warnings = %d, want 2 (%v)", len(res.Warnings), res.Warnings)
	}
}

func TestParse_SPDX_22Normalize(t *testing.T) {
	doc := `{"spdxVersion":"SPDX-2.2","packages":[]}`
	if _, err := parser.NewRegistry().Parse(context.Background(), "spdx", "", []byte(doc)); err != nil {
		t.Errorf("SPDX-2.2: %v", err)
	}
}

func TestParse_SPDX_UnknownVersionFromDoc(t *testing.T) {
	// specVersion empty → version read from the doc via normalizeSPDXVersion's
	// default branch (returns the raw string) → validation rejects it.
	doc := `{"spdxVersion":"SPDX-9.9","packages":[]}`
	if _, err := parser.NewRegistry().Parse(context.Background(), "spdx", "", []byte(doc)); err == nil {
		t.Error("SPDX-9.9: want unsupported-version error")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
