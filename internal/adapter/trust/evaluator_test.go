package trust

import (
	"context"
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

type passTrustRepo struct{}

func (passTrustRepo) FindSBOMByDedupKey(context.Context, string, string) (string, bool, error) {
	return "", false, nil
}

func (passTrustRepo) FindVEXByDedupKey(context.Context, string, string) (string, bool, error) {
	return "", false, nil
}

func (passTrustRepo) ImageDigestExists(context.Context, string) (bool, error) {
	return true, nil
}

func (passTrustRepo) SBOMChecksumExists(context.Context, string) (bool, error) {
	return true, nil
}

func TestGateEvaluator(t *testing.T) {
	evaluator := GateEvaluator{Gate: &Gate{
		Verifier: StubVerifier{},
		Repo:     passTrustRepo{},
	}}
	outcome := evaluator.Evaluate(context.Background(), domain.RawArtifact{
		Kind:             domain.ArtifactKindSBOM,
		Format:           "cyclonedx",
		SpecVersion:      "1.4",
		RawDocument:      []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4"}`),
		ImageDigest:      "sha256:abc",
		CIJobID:          "job",
		CIPipelineURL:    "https://ci.example",
		SupplierIdentity: "team-a",
		ProductOwner:     "team-a",
	}, domain.TrustPolicyStandard)
	if !outcome.Accepted {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestGateEvaluatorNilGate(t *testing.T) {
	outcome := (GateEvaluator{}).Evaluate(context.Background(), domain.RawArtifact{}, domain.TrustPolicyStandard)
	if outcome.Accepted {
		t.Fatal("expected rejection")
	}
}
