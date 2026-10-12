package trust_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/themis-project/themis/internal/evidence/adapters/trust"
	"github.com/themis-project/themis/internal/evidence/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

func TestAdmit_Accepted(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX"}`)
	res, err := trust.Gate{}.Admit(trust.Artifact{
		Raw:        raw,
		Kind:       domain.KindSBOM,
		Provenance: domain.Provenance{Source: "trivy", ImageDigest: "sha256:abc"},
	})
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if res.Status != domain.TrustAccepted {
		t.Errorf("status = %q, want accepted (reason=%q)", res.Status, res.Reason)
	}
	if !res.Fingerprint.Equal(value.NewContentFingerprint(raw)) {
		t.Error("fingerprint mismatch")
	}
	if res.Provenance.Source != "trivy" {
		t.Errorf("provenance not carried: %+v", res.Provenance)
	}
}

func TestAdmit_ExpectedChecksum(t *testing.T) {
	raw := []byte(`{"a":1}`)
	fp := value.NewContentFingerprint(raw).String()

	// Matching checksum (with surrounding whitespace / mixed case) is accepted.
	res, err := trust.Gate{}.Admit(trust.Artifact{Raw: raw, Kind: domain.KindSBOM, ExpectedChecksum: "  " + fp + "  "})
	if err != nil {
		t.Fatalf("admit match: %v", err)
	}
	if res.Status != domain.TrustAccepted {
		t.Errorf("matching checksum: status = %q", res.Status)
	}

	// Mismatched checksum is rejected (not an error).
	res, err = trust.Gate{}.Admit(trust.Artifact{Raw: raw, Kind: domain.KindSBOM, ExpectedChecksum: "deadbeef"})
	if err != nil {
		t.Fatalf("admit mismatch: %v", err)
	}
	if res.Status != domain.TrustRejected || res.Reason == "" {
		t.Errorf("mismatch: status=%q reason=%q", res.Status, res.Reason)
	}
	if res.Fingerprint.IsZero() {
		t.Error("rejected result should still carry the computed fingerprint")
	}
}

func TestAdmit_NotJSON(t *testing.T) {
	res, err := trust.Gate{}.Admit(trust.Artifact{Raw: []byte("not json at all"), Kind: domain.KindSBOM})
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if res.Status != domain.TrustRejected || res.Reason == "" {
		t.Errorf("non-json: status=%q reason=%q", res.Status, res.Reason)
	}
}

// TestTrustGate_ScannerReport_ArrayShapedRefused is the 2026-10-05 regression on the
// OLD door (EDR-INTAKE-01 D11, tasks.md 2.4). The real array-shaped Cortex export is
// well-formed JSON, so `json.Valid` admitted it; it was filed as a curated scanner
// report, and Knowledge's evidence stream stopped on the poison event for 31 hours.
//
// The fixture is the intake corpus's own named regression body, read rather than
// restated: a hand-written approximation would prove the gate refuses something
// shaped like the incident, which is not the same claim.
func TestTrustGate_ScannerReport_ArrayShapedRefused(t *testing.T) {
	path := filepath.Join("..", "report", "testdata", "cortex", "2026-10-05-array.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the incident fixture: %v", err)
	}

	res, err := trust.Gate{}.Admit(trust.Artifact{Raw: raw, Kind: domain.KindScannerReport})
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if res.Status != domain.TrustRejected {
		t.Fatalf("status = %q, want rejected — this body must not reach the store through any door", res.Status)
	}
	if res.Reason == "" {
		t.Error("a refusal has to say what is wrong with the document")
	}
	if res.Fingerprint.IsZero() {
		t.Error("a rejected result still carries the computed fingerprint")
	}

	// The same bytes under a kind whose shape the gate does not own are unaffected:
	// this check is scoped to the curated contract, not to "arrays are suspicious".
	res, err = trust.Gate{}.Admit(trust.Artifact{Raw: raw, Kind: domain.KindVEX})
	if err != nil {
		t.Fatalf("admit vex: %v", err)
	}
	if res.Status != domain.TrustAccepted {
		t.Errorf("non-scanner kind: status = %q, want unchanged behaviour (reason=%q)", res.Status, res.Reason)
	}
}

func TestAdmit_ScannerReportCuratedShape(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		wantStatus domain.TrustStatus
	}{
		{"curated document", `{"findings":[{"cve":"CVE-2024-2961"}]}`, domain.TrustAccepted},
		// Zero findings is a shape the consumer reads; "nothing was found" is a
		// legitimate scan outcome, and refusing it here is the intake door's
		// `empty_report` decision, not the gate's.
		{"no findings yet a findings array", `{"findings":[]}`, domain.TrustAccepted},
		{"bare array", `[{"vulnerability_id":"CVE-1"}]`, domain.TrustRejected},
		{"scalar", `"a report"`, domain.TrustRejected},
		{"object with no findings", `{"results":[]}`, domain.TrustRejected},
		{"findings is not an array", `{"findings":{"cve":"CVE-1"}}`, domain.TrustRejected},
		{"findings is null", `{"findings":null}`, domain.TrustRejected},
		{"a finding is not an object", `{"findings":[{"cve":"CVE-1"}, "nope"]}`, domain.TrustRejected},
		{"a finding is an empty value", `{"findings":[""]}`, domain.TrustRejected},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := trust.Gate{}.Admit(trust.Artifact{Raw: []byte(c.raw), Kind: domain.KindScannerReport})
			if err != nil {
				t.Fatalf("admit: %v", err)
			}
			if res.Status != c.wantStatus {
				t.Fatalf("status = %q, want %q (reason=%q)", res.Status, c.wantStatus, res.Reason)
			}
			if c.wantStatus == domain.TrustRejected && res.Reason == "" {
				t.Error("rejected with no reason")
			}
		})
	}
}

func TestAdmit_Errors(t *testing.T) {
	if _, err := (trust.Gate{}).Admit(trust.Artifact{Raw: nil, Kind: domain.KindSBOM}); err == nil {
		t.Error("empty artifact: want error")
	}
	if _, err := (trust.Gate{}).Admit(trust.Artifact{Raw: []byte(`{}`), Kind: "bogus"}); err == nil {
		t.Error("invalid kind: want error")
	}
}
