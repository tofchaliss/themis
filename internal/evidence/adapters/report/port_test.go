package report

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/evidence/domain"
)

// TestPortDetect_EchoesTheACLsVocabulary — the kind and dialect cross the port as the
// ACL's own strings, because they are echoed to the client as `detected_kind` and
// `detected_format` and not as Evidence's filing kinds.
func TestPortDetect_EchoesTheACLsVocabulary(t *testing.T) {
	kind, dialect, err := Port{}.Detect("", []byte(`{"spdxVersion":"SPDX-2.3"}`))
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
			_, _, err := Port{}.Detect("", []byte(tc.body))
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

	curated, stats, convertedBy, digest, err := Port{}.Convert(string(DialectCortexCSV), body, observed)
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
	_, _, convertedBy, digest, err := Port{}.Convert(string(DialectCurated), body, time.Time{})
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
	_, _, _, _, err := Port{}.Convert("made-up", []byte(`{}`), time.Time{})
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
	_, _, _, _, err := Port{}.Convert(string(DialectCortexCSV), body, time.Time{})
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
	_, _, _, _, err := Port{}.Convert(string(DialectCortexJSON), body, time.Time{})
	re, ok := domain.AsReject(err)
	if !ok || re.Reason != domain.ReasonSourceInvalid {
		t.Fatalf("error = %v, want source_invalid", err)
	}
	if !strings.Contains(re.Detail, "1") {
		t.Errorf("detail %q does not name the element index", re.Detail)
	}
}
