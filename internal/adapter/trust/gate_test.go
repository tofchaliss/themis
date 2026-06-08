package trust

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

const (
	cycloneDoc = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`
	spdxDoc    = `{"spdxVersion":"SPDX-2.3","packages":[]}`
	openvexDoc = `{"@context":"https://openvex.dev/ns","statements":[]}`
	csafDoc    = `{"document":{"category":"csaf_vex"}}`
)

func testGate(t *testing.T) *Gate {
	t.Helper()
	return &Gate{
		Verifier: StubVerifier{},
		Repo:     NewMemoryRepository(),
		Audit:    NewMemoryAuditRecorder(),
	}
}

func baseSBOM(doc string) domain.RawArtifact {
	return domain.RawArtifact{
		Kind:             domain.ArtifactKindSBOM,
		Format:           "cyclonedx",
		SpecVersion:      "1.5",
		RawDocument:      []byte(doc),
		ImageDigest:      "sha256:abc",
		CIJobID:          "job-1",
		CIPipelineURL:    "https://ci.example/run/1",
		SupplierIdentity: "team-a",
		ProductOwner:     "team-a",
		Actor:            "tester",
		SourceIP:         "127.0.0.1",
	}
}

func TestStubVerifierUnsignedAndUnverified(t *testing.T) {
	verifier := StubVerifier{}
	unsigned, err := verifier.Verify(context.Background(), domain.RawArtifact{RawDocument: []byte("x")})
	if err != nil || unsigned.Status != domain.TrustStatusUnsigned {
		t.Fatalf("unsigned result = %+v, err = %v", unsigned, err)
	}

	signed, err := verifier.Verify(context.Background(), domain.RawArtifact{
		RawDocument: []byte("x"),
		Signature:   "sig",
	})
	if err != nil || signed.Status != domain.TrustStatusUnverified {
		t.Fatalf("signed result = %+v, err = %v", signed, err)
	}
}

func TestSchemaValidationFormats(t *testing.T) {
	tests := []struct {
		format string
		doc    string
	}{
		{format: "cyclonedx", doc: cycloneDoc},
		{format: "spdx", doc: spdxDoc},
		{format: "openvex", doc: openvexDoc},
		{format: "csaf", doc: csafDoc},
	}
	for _, tt := range tests {
		if err := validateDocument(tt.format, []byte(tt.doc)); err != nil {
			t.Fatalf("format %s: %v", tt.format, err)
		}
	}
	if err := validateDocument("cyclonedx", []byte(`{"specVersion":"1.5"}`)); err == nil {
		t.Fatal("expected schema validation error")
	}
	if err := validateDocument("unknown", []byte("{}")); err == nil {
		t.Fatal("expected unsupported format error")
	}
}

func TestValidateSpecVersion(t *testing.T) {
	if err := validateSpecVersion("cyclonedx", "1.6"); err != nil {
		t.Fatal(err)
	}
	if err := validateSpecVersion("cyclonedx", "9.9"); err == nil {
		t.Fatal("expected unsupported version error")
	}
	if err := validateSpecVersion("cyclonedx", ""); err == nil {
		t.Fatal("expected missing version error")
	}
}

func TestGateAcceptsSignedSBOMUnderStandardPolicy(t *testing.T) {
	gate := testGate(t)
	repo := gate.Repo.(*MemoryRepository)
	repo.SeedImage("sha256:abc")

	artifact := baseSBOM(cycloneDoc)
	artifact.Signature = "stub-signature"
	outcome := gate.Evaluate(context.Background(), artifact, domain.TrustPolicyStandard)
	if !outcome.Accepted || outcome.HTTPStatus != 202 {
		t.Fatalf("outcome = %+v", outcome)
	}
	if outcome.Result.Status != domain.TrustStatusUnverified {
		t.Fatalf("status = %q", outcome.Result.Status)
	}
}

func TestGateRejectsChecksumMismatch(t *testing.T) {
	gate := testGate(t)
	artifact := baseSBOM(cycloneDoc)
	artifact.ExpectedChecksum = "deadbeef"
	outcome := gate.Evaluate(context.Background(), artifact, domain.TrustPolicyStandard)
	if outcome.Accepted || outcome.HTTPStatus != 422 {
		t.Fatalf("outcome = %+v", outcome)
	}
	if gate.Audit.(*MemoryAuditRecorder).Count(domain.AuditActionSignatureFailure) != 1 {
		t.Fatal("expected signature failure audit")
	}
}

func TestGateDuplicateSBOM(t *testing.T) {
	gate := testGate(t)
	repo := gate.Repo.(*MemoryRepository)
	repo.SeedSBOM("doc-1", "sha256:abc", checksumSHA256([]byte(cycloneDoc)))

	outcome := gate.Evaluate(context.Background(), baseSBOM(cycloneDoc), domain.TrustPolicyStandard)
	if !outcome.Accepted || outcome.HTTPStatus != 200 || outcome.DuplicateID != "doc-1" {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestGateRejectsUnknownImageDigest(t *testing.T) {
	gate := testGate(t)
	outcome := gate.Evaluate(context.Background(), baseSBOM(cycloneDoc), domain.TrustPolicyStandard)
	if outcome.Accepted || outcome.Message != "image not found — ingest parent first" {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestGateStrictRejectsUnsigned(t *testing.T) {
	gate := testGate(t)
	repo := gate.Repo.(*MemoryRepository)
	repo.SeedImage("sha256:abc")

	outcome := gate.Evaluate(context.Background(), baseSBOM(cycloneDoc), domain.TrustPolicyStrict)
	if outcome.Accepted {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestGatePermissiveAcceptsUnsignedWithMinimalProvenance(t *testing.T) {
	gate := testGate(t)
	repo := gate.Repo.(*MemoryRepository)
	repo.SeedImage("sha256:abc")

	artifact := baseSBOM(cycloneDoc)
	artifact.CIJobID = ""
	artifact.CIPipelineURL = ""
	artifact.SupplierIdentity = ""
	outcome := gate.Evaluate(context.Background(), artifact, domain.TrustPolicyPermissive)
	if !outcome.Accepted || outcome.Result.Status != domain.TrustStatusUnsigned {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestGateStandardWarnsOnMissingProvenance(t *testing.T) {
	gate := testGate(t)
	repo := gate.Repo.(*MemoryRepository)
	repo.SeedImage("sha256:abc")

	artifact := baseSBOM(cycloneDoc)
	artifact.CIJobID = ""
	outcome := gate.Evaluate(context.Background(), artifact, domain.TrustPolicyStandard)
	if !outcome.Accepted || len(outcome.Result.Warnings) == 0 {
		t.Fatalf("outcome = %+v", outcome)
	}
	if gate.Audit.(*MemoryAuditRecorder).Count(domain.AuditActionArtifactWarning) != 1 {
		t.Fatal("expected warning audit")
	}
}

func TestGateStandardWarnsOnUnknownSupplier(t *testing.T) {
	gate := testGate(t)
	repo := gate.Repo.(*MemoryRepository)
	repo.SeedImage("sha256:abc")

	artifact := baseSBOM(cycloneDoc)
	artifact.SupplierIdentity = "unknown-vendor"
	artifact.ProductOwner = "team-a"
	outcome := gate.Evaluate(context.Background(), artifact, domain.TrustPolicyStandard)
	if !outcome.Accepted || len(outcome.Result.Warnings) == 0 {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestGateStrictRejectsUnknownSupplier(t *testing.T) {
	gate := testGate(t)
	repo := gate.Repo.(*MemoryRepository)
	repo.SeedImage("sha256:abc")

	artifact := baseSBOM(cycloneDoc)
	artifact.SupplierIdentity = "unknown-vendor"
	outcome := gate.Evaluate(context.Background(), artifact, domain.TrustPolicyStrict)
	if outcome.Accepted {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestGateVEXIntegrityChain(t *testing.T) {
	gate := testGate(t)
	repo := gate.Repo.(*MemoryRepository)
	checksum := checksumSHA256([]byte(openvexDoc))
	repo.SeedSBOM("sbom-1", "sha256:abc", checksum)

	artifact := domain.RawArtifact{
		Kind:             domain.ArtifactKindVEX,
		Format:           "openvex",
		SpecVersion:      "1.0.0",
		RawDocument:      []byte(openvexDoc),
		SBOMChecksum:     checksum,
		CIJobID:          "job-1",
		CIPipelineURL:    "https://ci.example/run/1",
		SupplierIdentity: "team-a",
		ProductOwner:     "team-a",
		Actor:            "tester",
	}
	outcome := gate.Evaluate(context.Background(), artifact, domain.TrustPolicyStandard)
	if !outcome.Accepted {
		t.Fatalf("outcome = %+v", outcome)
	}

	artifact.SBOMChecksum = "missing"
	outcome = gate.Evaluate(context.Background(), artifact, domain.TrustPolicyStandard)
	if outcome.Accepted || outcome.Message != "SBOM not found — ingest parent first" {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestGateRepositoryFailure(t *testing.T) {
	gate := &Gate{
		Verifier: StubVerifier{},
		Repo:     failingRepository{},
	}
	outcome := gate.Evaluate(context.Background(), baseSBOM(cycloneDoc), domain.TrustPolicyStandard)
	if outcome.Accepted || outcome.HTTPStatus != 500 {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestGateUnsupportedArtifactKind(t *testing.T) {
	gate := testGate(t)
	artifact := baseSBOM(cycloneDoc)
	artifact.Kind = "unknown"
	outcome := gate.Evaluate(context.Background(), artifact, domain.TrustPolicyStandard)
	if outcome.Accepted {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestGateNilAuditRecorder(t *testing.T) {
	gate := &Gate{
		Verifier: StubVerifier{},
		Repo:     NewMemoryRepository(),
	}
	repo := gate.Repo.(*MemoryRepository)
	repo.SeedImage("sha256:abc")
	outcome := gate.Evaluate(context.Background(), baseSBOM(cycloneDoc), domain.TrustPolicyPermissive)
	if !outcome.Accepted {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestValidateSpecVersionUnsupportedFormat(t *testing.T) {
	if err := validateSpecVersion("nope", "1.0"); err == nil {
		t.Fatal("expected unsupported format error")
	}
}

func TestGateStrictRejectsMissingProvenance(t *testing.T) {
	gate := testGate(t)
	repo := gate.Repo.(*MemoryRepository)
	repo.SeedImage("sha256:abc")

	artifact := baseSBOM(cycloneDoc)
	artifact.CIJobID = ""
	artifact.Signature = "sig"
	outcome := gate.Evaluate(context.Background(), artifact, domain.TrustPolicyStrict)
	if outcome.Accepted {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestGateVEXDuplicate(t *testing.T) {
	gate := testGate(t)
	repo := gate.Repo.(*MemoryRepository)
	sbomChecksum := checksumSHA256([]byte(cycloneDoc))
	vexChecksum := checksumSHA256([]byte(openvexDoc))
	repo.SeedVEX("vex-1", sbomChecksum, vexChecksum)

	artifact := domain.RawArtifact{
		Kind:             domain.ArtifactKindVEX,
		Format:           "openvex",
		SpecVersion:      "1.0.0",
		RawDocument:      []byte(openvexDoc),
		SBOMChecksum:     sbomChecksum,
		CIJobID:          "job-1",
		CIPipelineURL:    "https://ci.example/run/1",
		SupplierIdentity: "team-a",
		ProductOwner:     "team-a",
	}
	outcome := gate.Evaluate(context.Background(), artifact, domain.TrustPolicyStandard)
	if !outcome.Accepted || outcome.DuplicateID != "vex-1" {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestGateStandardAllowsEmptySupplier(t *testing.T) {
	gate := testGate(t)
	repo := gate.Repo.(*MemoryRepository)
	repo.SeedImage("sha256:abc")

	artifact := baseSBOM(cycloneDoc)
	artifact.SupplierIdentity = ""
	outcome := gate.Evaluate(context.Background(), artifact, domain.TrustPolicyStandard)
	if !outcome.Accepted {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestGateVEXIntegrityRepositoryError(t *testing.T) {
	repo := NewMemoryRepository()
	gate := &Gate{
		Verifier: StubVerifier{},
		Repo:     &vexChainFailRepository{MemoryRepository: repo},
	}
	artifact := domain.RawArtifact{
		Kind:           domain.ArtifactKindVEX,
		Format:         "openvex",
		SpecVersion:    "1.0.0",
		RawDocument:    []byte(openvexDoc),
		SBOMChecksum:   "sbom-checksum",
	}
	outcome := gate.Evaluate(context.Background(), artifact, domain.TrustPolicyStandard)
	if outcome.Accepted {
		t.Fatalf("outcome = %+v", outcome)
	}
}

type vexChainFailRepository struct {
	*MemoryRepository
}

func (r *vexChainFailRepository) SBOMChecksumExists(context.Context, string) (bool, error) {
	return false, ErrRepository
}

func TestGateTrustedSupplierList(t *testing.T) {
	gate := testGate(t)
	repo := gate.Repo.(*MemoryRepository)
	repo.SeedImage("sha256:abc")

	artifact := baseSBOM(cycloneDoc)
	artifact.SupplierIdentity = "vendor-x"
	artifact.TrustedSuppliers = []string{"vendor-x"}
	outcome := gate.Evaluate(context.Background(), artifact, domain.TrustPolicyStandard)
	if !outcome.Accepted || len(outcome.Result.Warnings) != 0 {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestGateVerifierFailure(t *testing.T) {
	gate := &Gate{
		Verifier: failingVerifier{},
		Repo:     NewMemoryRepository(),
		Audit:    NewMemoryAuditRecorder(),
	}
	repo := gate.Repo.(*MemoryRepository)
	repo.SeedImage("sha256:abc")
	outcome := gate.Evaluate(context.Background(), baseSBOM(cycloneDoc), domain.TrustPolicyStandard)
	if outcome.Accepted || outcome.HTTPStatus != 500 {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestGateVEXRepositoryFailure(t *testing.T) {
	gate := &Gate{
		Verifier: StubVerifier{},
		Repo:     failingRepository{},
	}
	artifact := domain.RawArtifact{
		Kind:        domain.ArtifactKindVEX,
		Format:      "openvex",
		SpecVersion: "1.0.0",
		RawDocument: []byte(openvexDoc),
	}
	outcome := gate.Evaluate(context.Background(), artifact, domain.TrustPolicyStandard)
	if outcome.Accepted || outcome.HTTPStatus != 500 {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestValidateIntegrityChainMissingReferences(t *testing.T) {
	gate := testGate(t)
	repo := gate.Repo.(*MemoryRepository)
	repo.SeedImage("sha256:abc")

	sbom := baseSBOM(cycloneDoc)
	sbom.ImageDigest = ""
	outcome := gate.Evaluate(context.Background(), sbom, domain.TrustPolicyStandard)
	if outcome.Accepted {
		t.Fatalf("outcome = %+v", outcome)
	}

	vex := domain.RawArtifact{
		Kind:        domain.ArtifactKindVEX,
		Format:      "openvex",
		SpecVersion: "1.0.0",
		RawDocument: []byte(openvexDoc),
	}
	outcome = gate.Evaluate(context.Background(), vex, domain.TrustPolicyStandard)
	if outcome.Accepted {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestMemoryRepositorySeedVEX(t *testing.T) {
	repo := NewMemoryRepository()
	repo.SeedVEX("vex-1", "sbom-checksum", "doc-checksum")
	id, found, err := repo.FindVEXByDedupKey(context.Background(), "sbom-checksum", "doc-checksum")
	if err != nil || !found || id != "vex-1" {
		t.Fatalf("FindVEXByDedupKey() = %q, %v, %v", id, found, err)
	}
}

func TestFailingRepositoryMethods(t *testing.T) {
	repo := failingRepository{}
	ctx := context.Background()
	if _, _, err := repo.FindVEXByDedupKey(ctx, "a", "b"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := repo.ImageDigestExists(ctx, "a"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := repo.SBOMChecksumExists(ctx, "a"); err == nil {
		t.Fatal("expected error")
	}
}

type failingVerifier struct{}

func (failingVerifier) Verify(context.Context, domain.RawArtifact) (domain.TrustResult, error) {
	return domain.TrustResult{}, errors.New("verify failed")
}

func TestGateStrictAcceptsSignedArtifact(t *testing.T) {
	gate := testGate(t)
	repo := gate.Repo.(*MemoryRepository)
	repo.SeedImage("sha256:abc")

	artifact := baseSBOM(cycloneDoc)
	artifact.Signature = "sig"
	outcome := gate.Evaluate(context.Background(), artifact, domain.TrustPolicyStrict)
	if !outcome.Accepted {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestGateIntegrityRepositoryError(t *testing.T) {
	repo := NewMemoryRepository()
	gate := &Gate{
		Verifier: StubVerifier{},
		Repo: &integrityFailRepository{MemoryRepository: repo},
	}
	artifact := baseSBOM(cycloneDoc)
	artifact.ImageDigest = "sha256:abc"
	outcome := gate.Evaluate(context.Background(), artifact, domain.TrustPolicyStandard)
	if outcome.Accepted || outcome.HTTPStatus != 422 {
		t.Fatalf("outcome = %+v", outcome)
	}
}

type integrityFailRepository struct {
	*MemoryRepository
}

func (r *integrityFailRepository) ImageDigestExists(context.Context, string) (bool, error) {
	return false, ErrRepository
}

func TestGateAllDocumentFormatsAccepted(t *testing.T) {
	tests := []struct {
		name    string
		format  string
		version string
		doc     string
		kind    domain.ArtifactKind
	}{
		{name: "cyclonedx", format: "cyclonedx", version: "1.4", doc: `{"bomFormat":"CycloneDX","specVersion":"1.4","components":[]}`, kind: domain.ArtifactKindSBOM},
		{name: "spdx", format: "spdx", version: "SPDX-2.3", doc: spdxDoc, kind: domain.ArtifactKindSBOM},
		{name: "openvex", format: "openvex", version: "1.0.0", doc: openvexDoc, kind: domain.ArtifactKindVEX},
		{name: "csaf", format: "csaf", version: "2.0", doc: csafDoc, kind: domain.ArtifactKindVEX},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gate := testGate(t)
			repo := gate.Repo.(*MemoryRepository)
			repo.SeedImage("sha256:abc")
			checksum := checksumSHA256([]byte(tt.doc))
			repo.SeedSBOM("sbom-1", "sha256:abc", checksum)

			artifact := domain.RawArtifact{
				Kind:             tt.kind,
				Format:           tt.format,
				SpecVersion:      tt.version,
				RawDocument:      []byte(tt.doc),
				ImageDigest:      "sha256:abc",
				SBOMChecksum:     checksum,
				CIJobID:          "job",
				CIPipelineURL:    "https://ci.example",
				SupplierIdentity: "team-a",
				ProductOwner:     "team-a",
			}
			if tt.kind == domain.ArtifactKindVEX {
				artifact.ImageDigest = ""
			}
			outcome := gate.Evaluate(context.Background(), artifact, domain.TrustPolicyPermissive)
			if !outcome.Accepted {
				t.Fatalf("outcome = %+v", outcome)
			}
		})
	}
}

func TestGateRejectsInvalidJSONDocument(t *testing.T) {
	gate := testGate(t)
	artifact := baseSBOM("{")
	outcome := gate.Evaluate(context.Background(), artifact, domain.TrustPolicyStandard)
	if outcome.Accepted || outcome.HTTPStatus != 400 {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestGateRejectsUnsupportedSpecVersion(t *testing.T) {
	gate := testGate(t)
	artifact := baseSBOM(cycloneDoc)
	artifact.SpecVersion = "9.9"
	outcome := gate.Evaluate(context.Background(), artifact, domain.TrustPolicyStandard)
	if outcome.Accepted || outcome.HTTPStatus != 422 {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestValidateProvenanceMissingFieldsIndividually(t *testing.T) {
	base := baseSBOM(cycloneDoc)
	cases := []domain.RawArtifact{
		func() domain.RawArtifact { a := base; a.CIJobID = ""; return a }(),
		func() domain.RawArtifact { a := base; a.CIPipelineURL = ""; return a }(),
		func() domain.RawArtifact { a := base; a.SupplierIdentity = ""; return a }(),
	}
	for i, artifact := range cases {
		warnings := validateProvenance(artifact, domain.TrustPolicyStandard)
		if len(warnings) == 0 {
			t.Fatalf("case %d: expected provenance warnings", i)
		}
	}
}

func TestValidateIntegrityChainUnsupportedKind(t *testing.T) {
	gate := testGate(t)
	err := gate.validateIntegrityChain(context.Background(), domain.RawArtifact{Kind: "other"})
	if err == nil {
		t.Fatal("expected unsupported kind error")
	}
}

func TestValidateProvenancePermissive(t *testing.T) {
	if warnings := validateProvenance(domain.RawArtifact{}, domain.TrustPolicyPermissive); warnings != nil {
		t.Fatalf("warnings = %v", warnings)
	}
}
