package report

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/evidence/domain"
)

// TestPortDetect_EchoesTheACLsVocabulary — the kind and dialect cross the port as the
// ACL's own strings, because they are echoed to the client as `detected_kind` and
// `detected_format` and not as Evidence's filing kinds.
func TestPortDetect_EchoesTheACLsVocabulary(t *testing.T) {
	kind, dialect, err := Port{}.Detect("", []byte(`{"spdxVersion":"SPDX-2.3"}`), "")
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if kind != "sbom" || dialect != "spdx" {
		t.Errorf("detected %q/%q, want sbom/spdx", kind, dialect)
	}
}

// TestPortDetect_RefusesByNameWithTheReasonStrippedOutOfTheDetail is the 2026-09-22
// lesson at a port boundary. The sentinels here are NAMED after their reason, so
// passing the wrapped text straight through as `detail` would ship the reason inside
// its own elaboration — which is how a closed enum becomes free text and every
// consumer's table lookup misses.
func TestPortDetect_RefusesByNameWithTheReasonStrippedOutOfTheDetail(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		reason domain.RejectReason
	}{
		{"a body Themis cannot name", `{"vendor":"who?"}`, domain.ReasonUnrecognisedFormat},
		// An empty array is `empty_report`, not `unrecognised_format`: the fallback
		// the app would otherwise apply names the step, and the ACL knows better.
		{"an empty JSON array", `[]`, domain.ReasonEmptyReport},
		{"unparseable JSON", `{"findings":`, domain.ReasonMalformedBody},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Port{}.Detect("", []byte(tc.body), "")
			re, ok := domain.AsReject(err)
			if !ok {
				t.Fatalf("error = %v, want a reason-carrying refusal", err)
			}
			if re.Reason != tc.reason {
				t.Errorf("reason = %q, want %q", re.Reason, tc.reason)
			}
			if re.Detail == "" {
				t.Error("detail is empty; a refusal that names nothing is the defect")
			}
			if strings.HasPrefix(re.Detail, string(tc.reason)) {
				t.Errorf("detail %q repeats its own reason; the pair must stay two fields", re.Detail)
			}
		})
	}
}

// TestPortConvert_CarriesTheConverterAndTheSOURCEDigest — the digest is over the
// SUBMITTED bytes, which for a converted submission are not the filed bytes (D2).
// That is the whole of what makes the provenance verifiable.
func TestPortConvert_CarriesTheConverterAndTheSOURCEDigest(t *testing.T) {
	body := []byte(cortexCSVHeader + "a,CVE-1,pkg:rpm/redhat/zlib@1.2.11,zlib,1.2.11\n")
	observed := time.Date(2026, 9, 29, 7, 23, 22, 0, time.UTC)

	conv, err := Port{}.Convert(string(KindReport), string(DialectCortexCSV), body, observed)
	curated, stats, convertedBy, digest := conv.Document, conv.Stats, conv.ConvertedBy, conv.SourceDigest
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if convertedBy != cortexVersion {
		t.Errorf("converted_by = %q, want %q", convertedBy, cortexVersion)
	}
	sum := sha256.Sum256(body)
	if want := hex.EncodeToString(sum[:]); digest != want {
		t.Errorf("source_digest = %q, want the SHA-256 of the submitted bytes %q", digest, want)
	}
	if stats.FindingsTotal != 1 || stats.FindingsSkipped != 0 {
		t.Errorf("stats = %+v, want 1 of 1 kept", stats)
	}
	if !strings.Contains(string(curated), "CVE-1") {
		t.Errorf("curated document does not carry the finding: %s", curated)
	}
}

// TestPortConvert_PassThroughStillRecordsADigest — the source IS the document there,
// and recording its digest costs nothing while keeping one provenance shape for both
// roads.
func TestPortConvert_PassThroughStillRecordsADigest(t *testing.T) {
	body := []byte(`{"findings":[{"cve":"CVE-1","observed_at":"2026-09-29T07:23:22Z","component":{"purl":"pkg:rpm/redhat/zlib@1.2.11"}}]}`)
	conv, err := Port{}.Convert(string(KindReport), string(DialectCurated), body, time.Time{})
	convertedBy, digest := conv.ConvertedBy, conv.SourceDigest
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if convertedBy != "" {
		t.Errorf("converted_by = %q, want empty for a pass-through", convertedBy)
	}
	if len(digest) != 64 {
		t.Errorf("source_digest = %q, want a lowercase-hex SHA-256", digest)
	}
}

// TestPortConvert_RefusesADialectWithNoConverter — unreachable through Detect, which
// is why it is asserted: filing a document with a converter nobody chose is how an
// unreadable one lands.
func TestPortConvert_RefusesADialectWithNoConverter(t *testing.T) {
	_, err := Port{}.Convert(string(KindReport), "made-up", []byte(`{}`), time.Time{})
	re, ok := domain.AsReject(err)
	if !ok || re.Reason != domain.ReasonUnrecognisedFormat {
		t.Fatalf("error = %v, want unrecognised_format", err)
	}
}

// TestPortConvert_NoDerivableTimestampIsNamed — D3's refusal survives the port.
// Never `now`: a report stamped fresh and re-uploaded tomorrow is a second scan of
// the same image that nobody can tell apart.
func TestPortConvert_NoDerivableTimestampIsNamed(t *testing.T) {
	body := []byte(cortexCSVHeader + "a,CVE-1,pkg:rpm/redhat/zlib@1.2.11,zlib,1.2.11\n")
	_, err := Port{}.Convert(string(KindReport), string(DialectCortexCSV), body, time.Time{})
	re, ok := domain.AsReject(err)
	if !ok || re.Reason != domain.ReasonObservedAtUnderivable {
		t.Fatalf("error = %v, want observed_at_underivable", err)
	}
}

// TestAsReject_AnErrorCarryingNoReasonFallsBackToTheStep — unreachable through the
// real converters, which refuse only by sentinel, and asserted here because the
// alternative is inventing a diagnosis: naming the step an unnamed fault happened in
// is the most honest thing available.
func TestAsReject_AnErrorCarryingNoReasonFallsBackToTheStep(t *testing.T) {
	err := asReject(errorString("the disk went away"), domain.ReasonConversionFailed)
	re, ok := domain.AsReject(err)
	if !ok || re.Reason != domain.ReasonConversionFailed {
		t.Fatalf("error = %v, want the step's own reason", err)
	}
	if re.Detail != "the disk went away" {
		t.Errorf("detail = %q, want the cause verbatim", re.Detail)
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }

// TestPortConvert_StructurallyBrokenSourceIsSourceInvalid — the stage-2 refusal, with
// the element the converter could not read named in the detail.
func TestPortConvert_StructurallyBrokenSourceIsSourceInvalid(t *testing.T) {
	body := []byte(`[{"vulnerability_id":"CVE-1","package_purl":"pkg:rpm/redhat/zlib@1.2.11","origin_package_name":"zlib","last_observed":1759130602123},"not-an-object"]`)
	_, err := Port{}.Convert(string(KindReport), string(DialectCortexJSON), body, time.Time{})
	re, ok := domain.AsReject(err)
	if !ok || re.Reason != domain.ReasonSourceInvalid {
		t.Fatalf("error = %v, want source_invalid", err)
	}
	if !strings.Contains(re.Detail, "1") {
		t.Errorf("detail %q does not name the element index", re.Detail)
	}
}

// TestPortDetect_DeclaredKind — 2026-10-26 P1. A `.nessus` export is an SBOM unless
// `vuln-report` is declared; a declaration that agrees changes nothing; any other
// disagreement is refused by name, never silently obeyed.
func TestPortDetect_DeclaredKind(t *testing.T) {
	nessus := `<NessusClientData_v2/>`
	for _, tc := range []struct {
		name, body, declared, kind, dialect string
		reason                              domain.RejectReason
	}{
		{"a .nessus export, nothing declared", nessus, "", "sbom", "nessus", ""},
		{"a .nessus export declared sbom", nessus, "sbom", "sbom", "nessus", ""},
		{"a .nessus export declared vuln-report", nessus, "vuln-report", "vuln-report", "nessus", ""},
		{"an SPDX SBOM declared sbom", `{"spdxVersion":"SPDX-2.3"}`, "sbom", "sbom", "spdx", ""},
		{"an SPDX SBOM declared vuln-report", `{"spdxVersion":"SPDX-2.3"}`, "vuln-report", "", "", domain.ReasonDeclaredFormatMismatch},
		{"a curated report declared sbom", `{"findings":[]}`, "sbom", "", "", domain.ReasonDeclaredFormatMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kind, dialect, err := Port{}.Detect("", []byte(tc.body), tc.declared)
			if tc.reason != "" {
				re, ok := domain.AsReject(err)
				if !ok || re.Reason != tc.reason {
					t.Fatalf("error = %v, want %s", err, tc.reason)
				}
				if strings.HasPrefix(re.Detail, string(tc.reason)) {
					t.Errorf("detail %q repeats its own reason", re.Detail)
				}
				return
			}
			if err != nil || kind != tc.kind || dialect != tc.dialect {
				t.Errorf("Detect = %q/%q/%v, want %s/%s", kind, dialect, err, tc.kind, tc.dialect)
			}
		})
	}
}

// TestPortConvert_AStandardsSBOMPassesThroughUntouched — no converter, no digest, the
// submitted bytes: re-serializing would change the fingerprint that dedups a re-upload.
func TestPortConvert_AStandardsSBOMPassesThroughUntouched(t *testing.T) {
	for _, dialect := range []Dialect{DialectCycloneDX, DialectSPDX} {
		body := []byte(`{"any":"bytes"}`)
		conv, err := Port{}.Convert(string(KindSBOM), string(dialect), body, time.Time{})
		if err != nil {
			t.Fatalf("%s: %v", dialect, err)
		}
		if string(conv.Document) != string(body) || conv.Format != string(dialect) || conv.ConvertedBy != "" || conv.SourceDigest != "" {
			t.Errorf("%s: conversion = %+v, want the bytes back with no provenance", dialect, conv)
		}
	}
}

// TestPortConvert_ANessusSBOMIsFiledAsCycloneDX — P2: the document handed back is
// CycloneDX, named as such, with the conversion's provenance and the skip count.
func TestPortConvert_ANessusSBOMIsFiledAsCycloneDX(t *testing.T) {
	body := readFixture(t, "nessus", "inventory.input.nessus")
	conv, err := Port{}.Convert(string(KindSBOM), string(DialectNessus), body, time.Time{})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if conv.Format != "cyclonedx" || conv.ConvertedBy != "nessus-inventory@2" || conv.Stats.ComponentsSkipped != 4 || conv.Stats.ComponentsUnmanaged != 4 {
		t.Errorf("conversion = format %q, by %q, stats %+v", conv.Format, conv.ConvertedBy, conv.Stats)
	}
	sum := sha256.Sum256(body)
	if conv.SourceDigest != hex.EncodeToString(sum[:]) {
		t.Errorf("source_digest = %q, want the SHA-256 of the submitted bytes", conv.SourceDigest)
	}

	// The same export, declared a report, reads its findings instead.
	rep, err := Port{}.Convert(string(KindReport), string(DialectNessus), readFixture(t, "nessus", "sample.input.nessus"), time.Time{})
	if err != nil || rep.ConvertedBy != "nessus@2" || rep.Format != "nessus" {
		t.Errorf("report road = %+v / %v", rep, err)
	}
}

// TestPortConvert_AnSBOMDialectWithNoInventoryConverter — unreachable through Detect.
func TestPortConvert_AnSBOMDialectWithNoInventoryConverter(t *testing.T) {
	_, err := Port{}.Convert(string(KindSBOM), "trivy", []byte(`{}`), time.Time{})
	re, ok := domain.AsReject(err)
	if !ok || re.Reason != domain.ReasonUnrecognisedFormat {
		t.Fatalf("error = %v, want unrecognised_format", err)
	}
}

// The package-level Convert is the REPORT road; a `.nessus` body is an SBOM there too.
func TestConvert_RefusesANessusSBOM(t *testing.T) {
	_, _, err := Convert([]byte(`<NessusClientData_v2/>`), time.Time{})
	if !errors.Is(err, ErrUnrecognisedFormat) {
		t.Fatalf("err = %v, want unrecognised_format", err)
	}
}
