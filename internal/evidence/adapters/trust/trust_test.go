package trust_test

import (
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

func TestAdmit_Errors(t *testing.T) {
	if _, err := (trust.Gate{}).Admit(trust.Artifact{Raw: nil, Kind: domain.KindSBOM}); err == nil {
		t.Error("empty artifact: want error")
	}
	if _, err := (trust.Gate{}).Admit(trust.Artifact{Raw: []byte(`{}`), Kind: "bogus"}); err == nil {
		t.Error("invalid kind: want error")
	}
}
