package report

import (
	"errors"
	"testing"
	"time"
)

const cortexCSVHeader = "asset_name,vulnerability_id,package_purl,origin_package_name,package_version\n"

// TestDetectTruthTable walks D5a's closed table, one case per row plus the
// unrecognised row, plus the precedence pairs that make "first match wins" an
// observable property rather than a comment.
func TestDetectTruthTable(t *testing.T) {
	for _, tc := range []struct {
		name        string
		contentType string
		body        string
		kind        Kind
		dialect     Dialect
		err         error
	}{
		// Row 1.
		{
			name:        "text/csv with a Cortex header row",
			contentType: "text/csv",
			body:        cortexCSVHeader + "a,CVE-1,p,n,1\n",
			kind:        KindReport, dialect: DialectCortexCSV,
		},
		{
			name:        "text/csv with parameters",
			contentType: "text/csv; charset=utf-8",
			body:        cortexCSVHeader,
			kind:        KindReport, dialect: DialectCortexCSV,
		},
		{
			// The tolerance: curl's default content type must not hide a Cortex CSV.
			name: "a Cortex CSV with no declared content type",
			body: cortexCSVHeader + "a,CVE-1,p,n,1\n",
			kind: KindReport, dialect: DialectCortexCSV,
		},
		{
			name:        "text/csv whose header is not Cortex's",
			contentType: "text/csv",
			body:        "host,finding,when\nweb1,something,today\n",
			err:         ErrUnrecognisedFormat,
		},
		// Row 2.
		{
			name:    "CycloneDX",
			body:    `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`,
			kind:    KindSBOM,
			dialect: DialectCycloneDX,
		},
		// Row 5b (GUI-15).
		{
			name:    "Grype",
			body:    `{"matches":[],"descriptor":{"name":"grype","version":"0.80.0"}}`,
			kind:    KindReport,
			dialect: DialectGrype,
		},
		{
			name: "matches without a grype descriptor is not claimed",
			body: `{"matches":[{"x":1}],"descriptor":{"name":"other"}}`,
			err:  ErrUnrecognisedFormat,
		},
		// Row 1b (2026-10-24 amendment N1): the XML root decides, whatever the content type.
		// An SBOM by default since the 2026-10-26 amendment (P1).
		{
			name:        "a Nessus export declared as XML",
			contentType: "application/xml",
			body:        `<?xml version="1.0" encoding="UTF-8"?>` + "\n<NessusClientData_v2><Report/></NessusClientData_v2>",
			kind:        KindSBOM, dialect: DialectNessus,
		},
		{
			name: "a Nessus export with a BOM, a comment and no content type",
			body: "\xEF\xBB\xBF  <!-- exported --><NessusClientData_v2/>",
			kind: KindSBOM, dialect: DialectNessus,
		},
		// Row 1, Nessus header (2026-10-26 amendment C1).
		{
			name:        "a Nessus CSV declared text/csv",
			contentType: "text/csv; charset=utf-8",
			body:        nessusCSVHeader + "\n",
			kind:        KindReport, dialect: DialectNessusCSV,
		},
		{
			name: "a Nessus CSV with no content type",
			body: nessusCSVHeader + "\n",
			kind: KindReport, dialect: DialectNessusCSV,
		},
		{
			name:        "a CSV header carrying both the Cortex and the Nessus column sets",
			contentType: "text/csv",
			body:        nessusCSVHeader + ",vulnerability_id,package_purl,origin_package_name\n",
			err:         ErrUnrecognisedFormat,
		},
		{
			name: "both column sets with no content type",
			body: nessusCSVHeader + ",vulnerability_id,package_purl,origin_package_name\n",
			err:  ErrUnrecognisedFormat,
		},
		{
			name: "other XML is refused by its root",
			body: `<?xml version="1.0"?><NessusClientData><Report/></NessusClientData>`,
			err:  ErrUnrecognisedFormat,
		},
		{
			name: "XML that does not parse",
			body: `<NessusClientData_v2`,
			err:  ErrMalformedBody,
		},
		{
			name: "XML declaring an entity",
			body: `<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e "boom">]><NessusClientData_v2>&e;</NessusClientData_v2>`,
			err:  ErrMalformedBody,
		},
		{
			name: "XML with no root element",
			body: `<?xml version="1.0"?><!-- nothing -->`,
			err:  ErrMalformedBody,
		},
		{
			// Row 1 still wins: a body declared CSV is never tried as anything else.
			name:        "a Nessus export declared text/csv",
			contentType: "text/csv",
			body:        `<NessusClientData_v2/>`,
			err:         ErrUnrecognisedFormat,
		},
		// Row 3.
		{
			name:    "SPDX",
			body:    `{"spdxVersion":"SPDX-2.3","name":"x","packages":[]}`,
			kind:    KindSBOM,
			dialect: DialectSPDX,
		},
		// Row 4.
		{
			name:    "an already-curated report",
			body:    `{"findings":[]}`,
			kind:    KindReport,
			dialect: DialectCurated,
		},
		// Row 5, both discriminators.
		{
			name:    "Trivy with SchemaVersion",
			body:    `{"SchemaVersion":2,"Results":[]}`,
			kind:    KindReport,
			dialect: DialectTrivy,
		},
		{
			name:    "Trivy with ArtifactName",
			body:    `{"ArtifactName":"img:tag","Results":[]}`,
			kind:    KindReport,
			dialect: DialectTrivy,
		},
		{
			name: "Results with neither discriminator",
			body: `{"Results":[]}`,
			err:  ErrUnrecognisedFormat,
		},
		{
			name: "Results is not an array",
			body: `{"SchemaVersion":2,"Results":{}}`,
			err:  ErrUnrecognisedFormat,
		},
		// Row 6 — the body the 2026-10-05 incident was.
		{
			name:    "a Cortex JSON array",
			body:    `[{"vulnerability_id":"CVE-1","package_purl":"p","origin_package_name":"n"}]`,
			kind:    KindReport,
			dialect: DialectCortexJSON,
		},
		{
			name: "a JSON array of objects that are not Cortex records",
			body: `[{"id":1},{"id":2}]`,
			err:  ErrUnrecognisedFormat,
		},
		{
			name: "a JSON array of scalars",
			body: `["CVE-1","CVE-2"]`,
			err:  ErrUnrecognisedFormat,
		},
		{
			// CONVENTIONS R5: decided without indexing element zero.
			name: "an empty JSON array",
			body: `[]`,
			err:  ErrEmptyReport,
		},
		// Row 7 and the malformed cases.
		{
			name: "an unknown vendor object",
			body: `{"vendor":"acme","issues":[]}`,
			err:  ErrUnrecognisedFormat,
		},
		{
			name: "findings present but not an array",
			body: `{"findings":{}}`,
			err:  ErrUnrecognisedFormat,
		},
		{
			name: "plain prose",
			body: "this is not a report at all",
			err:  ErrUnrecognisedFormat,
		},
		{
			name: "empty body",
			body: "",
			err:  ErrUnrecognisedFormat,
		},
		{
			name: "an object that does not parse",
			body: `{"findings":`,
			err:  ErrMalformedBody,
		},
		{
			name: "an array that does not parse",
			body: `[{"vulnerability_id":`,
			err:  ErrMalformedBody,
		},
		// Precedence, which is the contract: first match wins.
		{
			name:    "spdxVersion beats findings",
			body:    `{"spdxVersion":"SPDX-2.3","findings":[]}`,
			kind:    KindSBOM,
			dialect: DialectSPDX,
		},
		{
			name:    "bomFormat beats spdxVersion",
			body:    `{"bomFormat":"CycloneDX","spdxVersion":"SPDX-2.3"}`,
			kind:    KindSBOM,
			dialect: DialectCycloneDX,
		},
		{
			name:    "a bomFormat that is not CycloneDX does not claim row 2",
			body:    `{"bomFormat":"SomethingElse","findings":[]}`,
			kind:    KindReport,
			dialect: DialectCurated,
		},
		{
			name:    "findings beats Results",
			body:    `{"findings":[],"SchemaVersion":2,"Results":[]}`,
			kind:    KindReport,
			dialect: DialectCurated,
		},
		{
			// A BOM-prefixed JSON body is not valid JSON (RFC 8259), and it is refused BY
			// NAME rather than silently repaired: stripping the BOM would change the bytes
			// that get fingerprinted, so "malformed" is the honest answer and the operator
			// re-exports instead of filing a document whose digest nobody can reproduce.
			name: "a leading byte-order mark makes a JSON body malformed, not unrecognised",
			body: "\xEF\xBB\xBF" + `{"bomFormat":"CycloneDX"}`,
			err:  ErrMalformedBody,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kind, dialect, err := Detect(tc.contentType, []byte(tc.body))
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("err = %v, want %v", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if kind != tc.kind || dialect != tc.dialect {
				t.Errorf("Detect = %s/%s, want %s/%s", kind, dialect, tc.kind, tc.dialect)
			}
		})
	}
}

// TestConvertRefusesAnSBOM: identification admits an SBOM to the intake door, but
// this package converts report dialects. Asking it for an SBOM is a caller error,
// reported rather than answered with an empty report.
func TestConvertRefusesAnSBOM(t *testing.T) {
	for _, body := range []string{
		`{"bomFormat":"CycloneDX","specVersion":"1.5"}`,
		`{"spdxVersion":"SPDX-2.3"}`,
	} {
		if _, _, err := Convert([]byte(body), time.Now()); !errors.Is(err, ErrUnrecognisedFormat) {
			t.Errorf("Convert(%s) err = %v, want ErrUnrecognisedFormat", body, err)
		}
	}
}

// TestConverterForIsClosed: one converter per report dialect and none for an SBOM
// (D4). A registration hook is how a second converter for a dialect gets added by
// accident, so the registry is a switch.
func TestConverterForIsClosed(t *testing.T) {
	for _, d := range []Dialect{DialectCurated, DialectCortexCSV, DialectCortexJSON, DialectTrivy, DialectGrype, DialectNessus} {
		conv, ok := ConverterFor(d)
		if !ok || conv == nil {
			t.Fatalf("ConverterFor(%s) = %v, %v", d, conv, ok)
		}
	}
	for _, d := range []Dialect{DialectSPDX, DialectCycloneDX, Dialect("snyk")} {
		if conv, ok := ConverterFor(d); ok {
			t.Errorf("ConverterFor(%s) returned %v, want no converter", d, conv)
		}
	}
}

func TestIsCSVContentType(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"text/csv", true},
		{"TEXT/CSV", true},
		{"text/csv; charset=utf-8", true},
		{"text/csv;charset=utf-8;;;broken", true},
		{"application/json", false},
		{"", false},
	} {
		if got := isCSVContentType(tc.in); got != tc.want {
			t.Errorf("isCSVContentType(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
