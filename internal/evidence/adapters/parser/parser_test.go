package parser_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// TestParse_SourceName_FormatParity proves the distro source-package name is captured from
// BOTH formats — Trivy's CycloneDX `aquasecurity:trivy:SrcName` property and the SPDX PURL
// `upstream=` qualifier — so the same image yields the same Source regardless of format.
func TestParse_SourceName_FormatParity(t *testing.T) {
	cdx := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{` +
		`"name":"openssl-libs","version":"1:1.1.1k-15.el8_10",` +
		`"purl":"pkg:rpm/rocky/openssl-libs@1.1.1k-15.el8_10?arch=x86_64&distro=rocky-8.9&epoch=1",` +
		`"properties":[{"name":"aquasecurity:trivy:PkgType","value":"rocky"},{"name":"aquasecurity:trivy:SrcName","value":"openssl"}]}]}`
	spdx := `{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"SPDXRef-1","name":"openssl-libs",` +
		`"versionInfo":"1:1.1.1k-17.el8_10","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER",` +
		`"referenceType":"purl","referenceLocator":"pkg:rpm/rocky/openssl-libs@1.1.1k-17.el8_10?arch=x86_64&distro=rocky-8.10&epoch=1&upstream=openssl-1.1.1k-17.el8_10.src.rpm"}]}]}`

	for _, tc := range []struct{ format, doc string }{{"cyclonedx", cdx}, {"spdx", spdx}} {
		res, err := parser.NewRegistry().Parse(context.Background(), tc.format, "", []byte(tc.doc))
		if err != nil {
			t.Fatalf("%s parse: %v", tc.format, err)
		}
		comps := res.Inventory.Components()
		if len(comps) != 1 {
			t.Fatalf("%s: components = %d, want 1 (%+v)", tc.format, len(comps), comps)
		}
		if comps[0].Source != "openssl" {
			t.Errorf("%s: Source = %q, want openssl (binary openssl-libs -> source openssl)", tc.format, comps[0].Source)
		}
	}
}

// TestParse_SourceName_HyphenatedAndAbsent covers a hyphenated source name and the no-source case.
func TestParse_SourceName_HyphenatedAndAbsent(t *testing.T) {
	spdx := `{"spdxVersion":"SPDX-2.3","packages":[` +
		`{"SPDXID":"a","name":"gcc","versionInfo":"12.2.1-7.el8","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:rpm/rocky/gcc@12.2.1-7.el8?distro=rocky-8.10&upstream=gcc-toolset-12-gcc-12.2.1-7.el8.src.rpm"}]},` +
		`{"SPDXID":"b","name":"bash","versionInfo":"4.4.20-4.el8","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:rpm/rocky/bash@4.4.20-4.el8?distro=rocky-8.10"}]}]}`
	res, err := parser.NewRegistry().Parse(context.Background(), "spdx", "", []byte(spdx))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := map[string]string{}
	for _, c := range res.Inventory.Components() {
		got[c.Name] = c.Source
	}
	if got["gcc"] != "gcc-toolset-12-gcc" {
		t.Errorf("hyphenated source = %q, want gcc-toolset-12-gcc", got["gcc"])
	}
	if got["bash"] != "" {
		t.Errorf("no-upstream source = %q, want empty", got["bash"])
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

// Syft's ownership-by-file-overlap arrives as SPDX OTHER + a comment marker; it becomes a
// first-class edge with its direction preserved (owner -> owned), because it is the
// Observed-grade evidence the ownership bridge runs on (EDR-VERDICT-01 D3). A bare OTHER
// without the marker proves nothing and drops.
func TestParse_SPDX_OwnershipRelationship(t *testing.T) {
	doc := []byte(`{
	  "spdxVersion": "SPDX-2.3",
	  "packages": [
	    {"SPDXID": "SPDXRef-rpm", "name": "platform-python-setuptools", "versionInfo": "39.2.0-9.el8_10",
	     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
	       "referenceLocator": "pkg:rpm/rhel/platform-python-setuptools@39.2.0-9.el8_10"}]},
	    {"SPDXID": "SPDXRef-py", "name": "setuptools", "versionInfo": "39.2.0",
	     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
	       "referenceLocator": "pkg:pypi/setuptools@39.2.0"}]}
	  ],
	  "relationships": [
	    {"spdxElementId": "SPDXRef-rpm", "relatedSpdxElement": "SPDXRef-py",
	     "relationshipType": "OTHER", "comment": "evident-by: ownership-by-file-overlap"},
	    {"spdxElementId": "SPDXRef-py", "relatedSpdxElement": "SPDXRef-rpm",
	     "relationshipType": "OTHER", "comment": "unrelated note"}
	  ]
	}`)
	res, err := parser.NewRegistry().Parse(context.Background(), "spdx", "", doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	edges := res.Inventory.Dependencies()
	if len(edges) != 1 {
		t.Fatalf("edges = %d, want 1 (the unmarked OTHER must drop): %+v", len(edges), edges)
	}
	e := edges[0]
	if e.Relationship != "ownership-by-file-overlap" ||
		e.From.String() != "pkg:rpm/rhel/platform-python-setuptools@39.2.0-9.el8_10" ||
		e.To.String() != "pkg:pypi/setuptools@39.2.0" {
		t.Errorf("edge = %+v, want owner->owned with the ownership relationship", e)
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

// The measured SPDX shape (2026-09-16): the same httpd package twice — once LIBRARY with a
// proper rpm purl, once APPLICATION with `supplier: NOASSERTION` and NO externalRefs — plus an
// ownership relationship pointing at the unidentified twin.
//
// Before EDR-IDENTITY-01 the unidentified entry was dropped with a warning, and because its
// SPDXID never entered the id→purl map, **the relationship went with it.** That edge carries
// Observed-grade bridge evidence (EDR-VERDICT-01 D3), so the document's strongest clearance
// signal was being discarded as a side effect of a naming defect.
func TestSPDX_PurllessTwinResolvesAndKeepsItsEdge(t *testing.T) {
	doc := []byte(`{
      "spdxVersion": "SPDX-2.3",
      "packages": [
        {"SPDXID": "SPDXRef-lib-httpd", "name": "httpd", "versionInfo": "2.4.57",
         "primaryPackagePurpose": "LIBRARY",
         "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                           "referenceLocator": "pkg:rpm/rocky/httpd@2.4.57"}]},
        {"SPDXID": "SPDXRef-app-httpd", "name": "httpd", "versionInfo": "2.4.57",
         "primaryPackagePurpose": "APPLICATION", "supplier": "NOASSERTION"},
        {"SPDXID": "SPDXRef-mod", "name": "mod_ssl", "versionInfo": "2.4.57",
         "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                           "referenceLocator": "pkg:rpm/rocky/mod_ssl@2.4.57"}]}
      ],
      "relationships": [
        {"spdxElementId": "SPDXRef-app-httpd", "relatedSpdxElement": "SPDXRef-mod",
         "relationshipType": "OTHER", "comment": "ownership-by-file-overlap"}
      ]
    }`)
	res, err := parser.NewRegistry().Parse(context.Background(), string(parser.FormatSPDX), "2.3", doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	comps := res.Inventory.Components()
	if len(comps) != 2 {
		t.Fatalf("components = %d, want 2 — the duplicate must NOT become a second subject", len(comps))
	}
	// The ownership edge survived by resolving onto the identified twin. This is the functional
	// gain: previously it vanished with the dropped entry.
	edges := res.Inventory.Dependencies()
	if len(edges) != 1 {
		t.Fatalf("edges = %d, want 1 — the edge must survive onto the resolved twin", len(edges))
	}
	if got := edges[0].From.String(); got != "pkg:rpm/rocky/httpd@2.4.57" {
		t.Errorf("edge from = %q, want the identified twin's purl", got)
	}
	// An exact duplicate is resolved, not unresolved, so it raises no warning.
	for _, w := range res.Warnings {
		if strings.Contains(w, "unresolved component identity") {
			t.Errorf("an exactly-resolvable twin must not warn: %q", w)
		}
	}
}

// A named entry with NO identified twin is retained as a WARNING rather than dropped in silence.
// It still does not enter the inventory — synthesizing an identity is forbidden (D3) — but the
// fact that the document named a component Themis cannot correlate is now visible (D6).
func TestSPDX_UnidentifiableComponentIsSurfacedNotSilent(t *testing.T) {
	doc := []byte(`{
      "spdxVersion": "SPDX-2.3",
      "packages": [
        {"SPDXID": "SPDXRef-mystery", "name": "inhouse-agent", "versionInfo": "3.1.0"}
      ]
    }`)
	res, err := parser.NewRegistry().Parse(context.Background(), string(parser.FormatSPDX), "2.3", doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if n := len(res.Inventory.Components()); n != 0 {
		t.Errorf("components = %d, want 0 — no identity means no inventory entry, and none is invented", n)
	}
	var found bool
	for _, w := range res.Warnings {
		if strings.Contains(w, "unresolved component identity") && strings.Contains(w, "inhouse-agent") {
			found = true
		}
	}
	if !found {
		t.Errorf("want an unresolved-identity warning naming the component; got %v", res.Warnings)
	}
}

// The CycloneDX door takes the SAME rule (EDR-IDENTITY-01 D4 — one rule, three doors). Its
// identifier is a bom-ref rather than an SPDXID, and an entry may carry neither a usable purl
// NOR a bom-ref, in which case the raw purl string stands in as the local id: it is only ever
// used to re-key a dependency edge, so a non-identity is harmless there and losing the edge is not.
func TestCycloneDX_PurllessTwinResolvesAndKeepsItsEdge(t *testing.T) {
	doc := []byte(`{
      "bomFormat": "CycloneDX", "specVersion": "1.5",
      "components": [
        {"bom-ref": "ref-good", "name": "httpd", "version": "2.4.57", "purl": "pkg:rpm/rocky/httpd@2.4.57"},
        {"bom-ref": "ref-app", "name": "httpd", "version": "2.4.57", "purl": "app:httpd"},
        {"name": "httpd", "version": "2.4.57", "purl": "app:httpd-no-ref"},
        {"bom-ref": "ref-mystery", "name": "inhouse-agent", "version": "3.1.0", "purl": "app:inhouse"}
      ],
      "dependencies": [
        {"ref": "ref-app", "dependsOn": ["ref-good"]}
      ]
    }`)
	res, err := parser.NewRegistry().Parse(context.Background(), string(parser.FormatCycloneDX), "1.5", doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if n := len(res.Inventory.Components()); n != 1 {
		t.Fatalf("components = %d, want 1 — three entries name one identified component", n)
	}
	// The dependency edge survived by resolving its bom-ref onto the identified twin.
	if n := len(res.Inventory.Dependencies()); n != 1 {
		t.Errorf("dependencies = %d, want 1 — the edge must survive onto the resolved twin", n)
	}
	// Only the genuinely unidentifiable entry is unresolved; the twins are resolved silently.
	var unresolved int
	for _, w := range res.Warnings {
		if strings.Contains(w, "unresolved component identity") {
			unresolved++
			if !strings.Contains(w, "inhouse-agent") {
				t.Errorf("unexpected unresolved entry: %q", w)
			}
		}
	}
	if unresolved != 1 {
		t.Errorf("unresolved warnings = %d, want 1 (inhouse-agent only); got %v", unresolved, res.Warnings)
	}
}
