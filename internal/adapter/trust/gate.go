package trust

import (
	"context"
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

// Gate orchestrates artifact trust validation.
type Gate struct {
	Verifier domain.SignatureVerifier
	Repo     domain.TrustRepository
	Audit    domain.AuditRecorder
}

// Evaluate runs the full trust gate for an artifact.
func (g *Gate) Evaluate(ctx context.Context, artifact domain.RawArtifact, policy domain.TrustPolicy) domain.GateOutcome {
	checksum := checksumSHA256(artifact.RawDocument)
	result := domain.TrustResult{ChecksumSHA256: checksum}

	if err := compareChecksum(checksum, artifact.ExpectedChecksum); err != nil {
		outcome := reject(result, 422, err.Error(), domain.TrustStatusFailed)
		g.record(ctx, artifact, domain.AuditActionSignatureFailure, outcome, nil)
		return outcome
	}

	if err := validateDocument(artifact.Format, artifact.RawDocument); err != nil {
		outcome := reject(result, 400, err.Error(), domain.TrustStatusFailed)
		g.record(ctx, artifact, domain.AuditActionArtifactRejected, outcome, nil)
		return outcome
	}

	if err := validateSpecVersion(artifact.Format, artifact.SpecVersion); err != nil {
		outcome := reject(result, 422, err.Error(), domain.TrustStatusFailed)
		g.record(ctx, artifact, domain.AuditActionArtifactRejected, outcome, nil)
		return outcome
	}

	dupID, duplicate, err := g.checkDuplicate(ctx, artifact, checksum)
	if err != nil {
		outcome := reject(result, 500, err.Error(), domain.TrustStatusFailed)
		g.record(ctx, artifact, domain.AuditActionArtifactRejected, outcome, nil)
		return outcome
	}
	if duplicate {
		result.Status = domain.TrustStatusVerified
		outcome := domain.GateOutcome{
			Accepted:    true,
			HTTPStatus:  200,
			Result:      result,
			DuplicateID: dupID,
			Message:     "duplicate artifact",
		}
		g.record(ctx, artifact, domain.AuditActionArtifactAccepted, outcome, nil)
		return outcome
	}

	if err := g.validateIntegrityChain(ctx, artifact); err != nil {
		outcome := reject(result, 422, err.Error(), domain.TrustStatusFailed)
		g.record(ctx, artifact, domain.AuditActionArtifactRejected, outcome, nil)
		return outcome
	}

	warnings := validateProvenance(artifact, policy)
	if len(warnings) > 0 && policy == domain.TrustPolicyStrict {
		outcome := reject(result, 422, strings.Join(warnings, "; "), domain.TrustStatusFailed)
		g.record(ctx, artifact, domain.AuditActionArtifactRejected, outcome, warnings)
		return outcome
	}

	supplierWarnings := validateSupplier(artifact, policy)
	warnings = append(warnings, supplierWarnings...)
	if len(supplierWarnings) > 0 && policy == domain.TrustPolicyStrict {
		outcome := reject(result, 422, strings.Join(supplierWarnings, "; "), domain.TrustStatusFailed)
		g.record(ctx, artifact, domain.AuditActionArtifactRejected, outcome, warnings)
		return outcome
	}

	verifyResult, err := g.Verifier.Verify(ctx, artifact)
	if err != nil {
		outcome := reject(result, 500, err.Error(), domain.TrustStatusFailed)
		g.record(ctx, artifact, domain.AuditActionArtifactRejected, outcome, warnings)
		return outcome
	}
	result.Status = verifyResult.Status
	result.SignatureVerified = verifyResult.SignatureVerified

	if err := enforceSignaturePolicy(result.Status, policy); err != nil {
		outcome := reject(result, 422, err.Error(), domain.TrustStatusFailed)
		g.record(ctx, artifact, domain.AuditActionArtifactRejected, outcome, warnings)
		return outcome
	}

	result.Warnings = warnings
	outcome := domain.GateOutcome{
		Accepted:   true,
		HTTPStatus: 202,
		Result:     result,
		Message:    "accepted",
	}
	action := domain.AuditActionArtifactAccepted
	if len(warnings) > 0 {
		action = domain.AuditActionArtifactWarning
	}
	g.record(ctx, artifact, action, outcome, warnings)
	return outcome
}

func (g *Gate) checkDuplicate(ctx context.Context, artifact domain.RawArtifact, checksum string) (string, bool, error) {
	switch artifact.Kind {
	case domain.ArtifactKindSBOM:
		return g.Repo.FindSBOMByDedupKey(ctx, artifact.ImageDigest, checksum)
	case domain.ArtifactKindVEX:
		return g.Repo.FindVEXByDedupKey(ctx, artifact.SBOMChecksum, checksum)
	default:
		return "", false, fmt.Errorf("unsupported artifact kind %q", artifact.Kind)
	}
}

func (g *Gate) validateIntegrityChain(ctx context.Context, artifact domain.RawArtifact) error {
	switch artifact.Kind {
	case domain.ArtifactKindSBOM:
		if artifact.ImageDigest == "" {
			return fmt.Errorf("image digest is required")
		}
		exists, err := g.Repo.ImageDigestExists(ctx, artifact.ImageDigest)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("image not found — ingest parent first")
		}
	case domain.ArtifactKindVEX:
		if artifact.SBOMChecksum == "" {
			return fmt.Errorf("sbom checksum is required")
		}
		exists, err := g.Repo.SBOMChecksumExists(ctx, artifact.SBOMChecksum)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("SBOM not found — ingest parent first")
		}
	default:
		return fmt.Errorf("unsupported artifact kind %q", artifact.Kind)
	}
	return nil
}

func (g *Gate) record(ctx context.Context, artifact domain.RawArtifact, action string, outcome domain.GateOutcome, warnings []string) {
	if g.Audit == nil {
		return
	}
	details := map[string]string{
		"message":       outcome.Message,
		"trust_status":  string(outcome.Result.Status),
		"format":        artifact.Format,
		"spec_version":  artifact.SpecVersion,
		"artifact_kind": string(artifact.Kind),
	}
	if outcome.DuplicateID != "" {
		details["duplicate_id"] = outcome.DuplicateID
	}
	for i, warning := range warnings {
		details[fmt.Sprintf("warning_%d", i+1)] = warning
	}
	_ = g.Audit.Record(ctx, domain.AuditEntry{
		Actor:        artifact.Actor,
		Action:       action,
		ResourceType: string(artifact.Kind),
		ResourceID:   outcome.DuplicateID,
		Details:      details,
		SourceIP:     artifact.SourceIP,
	})
}

func reject(result domain.TrustResult, status int, message string, trustStatus domain.TrustStatus) domain.GateOutcome {
	result.Status = trustStatus
	return domain.GateOutcome{
		Accepted:   false,
		HTTPStatus: status,
		Result:     result,
		Message:    message,
	}
}
