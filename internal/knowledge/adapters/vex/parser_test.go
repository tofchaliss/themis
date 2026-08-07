package vex_test

import (
	"testing"

	"github.com/themis-project/themis/internal/knowledge/adapters/vex"
)

func TestParseOpenVEX(t *testing.T) {
	raw := []byte(`{"statements":[
		{"vulnerability":{"name":"CVE-2024-1"},"products":[{"@id":"pkg:pypi/urllib3@1.0"},{"@id":"pkg:pypi/other"}],"status":"not_affected","justification":"vulnerable_code_not_present"},
		{"vulnerability":"CVE-2024-2","products":[{"@id":"pkg:deb/openssl"}],"status":"affected"},
		{"vulnerability":{"name":"CVE-2024-3"},"products":[{"@id":"pkg:x"}],"status":""},
		{"vulnerability":{"name":""},"products":[{"@id":"pkg:y"}],"status":"fixed"},
		{"vulnerability":{"name":"CVE-2024-4"},"products":[{"@id":""}],"status":"fixed"},
		{"products":[{"@id":"pkg:z"}],"status":"fixed"}
	]}`)
	stmts, err := vex.ParseOpenVEX(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Statement 1 → two (two products, object vuln); statement 2 → one (bare-string vuln); the
	// rest are skipped (empty status / empty name / empty product / no vulnerability).
	if len(stmts) != 3 {
		t.Fatalf("got %d statements, want 3: %+v", len(stmts), stmts)
	}
	if stmts[0].CVE != "CVE-2024-1" || stmts[0].Package != "pkg:pypi/urllib3@1.0" ||
		stmts[0].Status != "not_affected" || stmts[0].Justification != "vulnerable_code_not_present" {
		t.Errorf("stmt[0] = %+v", stmts[0])
	}
	if stmts[1].Package != "pkg:pypi/other" {
		t.Errorf("stmt[1] = %+v (second product of statement 1)", stmts[1])
	}
	if stmts[2].CVE != "CVE-2024-2" || stmts[2].Package != "pkg:deb/openssl" {
		t.Errorf("stmt[2] = %+v (bare-string vulnerability)", stmts[2])
	}
}

func TestParseOpenVEX_InvalidJSON(t *testing.T) {
	if _, err := vex.ParseOpenVEX([]byte(`{not json`)); err == nil {
		t.Error("invalid OpenVEX json must error")
	}
}

// TestParseOpenVEX_RoundTripsThemisOwnOutput is the C6 contract test.
//
// The document below is BYTE-FOR-BYTE what Communication's OpenVEX serializer emits — the same
// bytes its golden test asserts (`internal/communication/adapters/serializer/serializer_test.go`,
// TestOpenVEX). It is duplicated here as a literal rather than imported because Knowledge may
// not import Communication: contexts collaborate only through events and read APIs, and a test
// that reached across would break the rule the architecture test enforces. The two tests are
// the contract — change the emitted shape and the serializer's golden fails; stop reading that
// shape and this one does.
//
// Before this, the serializer emitted `"products": ["<uuid>"]` (bare strings) while the parser
// expected product objects, so Themis could not re-ingest its own published VEX: it yielded
// ZERO statements, silently.
func TestParseOpenVEX_RoundTripsThemisOwnOutput(t *testing.T) {
	published := []byte(`{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://themis.example/vex/fl-1",
  "author": "Themis",
  "version": 2,
  "statements": [
    {
      "vulnerability": {
        "name": "CVE-2024-1"
      },
      "products": [
        {
          "@id": "https://themis.example/release/rel-1",
          "subcomponents": [
            {
              "@id": "pkg:pypi/urllib3@1.26.20"
            }
          ]
        }
      ],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "status_notes": "vendor VEX confirms"
    }
  ]
}`)

	got, err := vex.ParseOpenVEX(published)
	if err != nil {
		t.Fatalf("ParseOpenVEX: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d statements, want 1 — Themis must be able to re-ingest its own output", len(got))
	}
	st := got[0]
	// The Package must be the PURL, not the release IRI. A statement keyed by the product id
	// would parse cleanly and then match no component in Knowledge — a round-trip that succeeds
	// syntactically and suppresses nothing is worse than one that fails loudly.
	if st.Package != "pkg:pypi/urllib3@1.26.20" {
		t.Errorf("Package = %q, want the component PURL from subcomponents", st.Package)
	}
	if st.CVE != "CVE-2024-1" || st.Status != "not_affected" {
		t.Errorf("statement = %+v, want CVE-2024-1 / not_affected", st)
	}
	if st.Justification != "vulnerable_code_not_in_execute_path" {
		t.Errorf("Justification = %q, want it carried through for explainability", st.Justification)
	}
}

// A third-party document with a PURL directly in the product id and no subcomponents must
// still parse. The spec does not require subcomponents, and refusing such documents would
// reject valid input to enforce a shape only Themis emits.
func TestParseOpenVEX_FallsBackToProductIDWithoutSubcomponents(t *testing.T) {
	raw := []byte(`{"statements":[{"vulnerability":{"name":"CVE-2024-2"},` +
		`"products":[{"@id":"pkg:npm/left-pad@1.3.0"}],"status":"not_affected"}]}`)
	got, err := vex.ParseOpenVEX(raw)
	if err != nil {
		t.Fatalf("ParseOpenVEX: %v", err)
	}
	if len(got) != 1 || got[0].Package != "pkg:npm/left-pad@1.3.0" {
		t.Fatalf("got %+v, want one statement keyed by the product PURL", got)
	}
}

// A product carrying several subcomponents yields one statement per package: each is a
// separate applicability decision against a different component.
func TestParseOpenVEX_OneStatementPerSubcomponent(t *testing.T) {
	raw := []byte(`{"statements":[{"vulnerability":{"name":"CVE-2024-3"},` +
		`"products":[{"@id":"https://themis.example/release/r1","subcomponents":[` +
		`{"@id":"pkg:pypi/a@1.0"},{"@id":"pkg:pypi/b@2.0"}]}],"status":"not_affected"}]}`)
	got, err := vex.ParseOpenVEX(raw)
	if err != nil {
		t.Fatalf("ParseOpenVEX: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d statements, want one per subcomponent", len(got))
	}
	for i, want := range []string{"pkg:pypi/a@1.0", "pkg:pypi/b@2.0"} {
		if got[i].Package != want {
			t.Errorf("statement %d package = %q, want %q", i, got[i].Package, want)
		}
	}
}
