package trust

import (
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

func validateProvenance(artifact domain.RawArtifact, policy domain.TrustPolicy) []string {
	if policy == domain.TrustPolicyPermissive {
		return nil
	}

	var missing []string
	if strings.TrimSpace(artifact.CIJobID) == "" {
		missing = append(missing, "ci_job_id")
	}
	if strings.TrimSpace(artifact.CIPipelineURL) == "" {
		missing = append(missing, "ci_pipeline_url")
	}
	if strings.TrimSpace(artifact.SupplierIdentity) == "" {
		missing = append(missing, "supplier_identity")
	}
	if len(missing) == 0 {
		return nil
	}
	return []string{"missing provenance fields: " + strings.Join(missing, ", ")}
}

func validateSupplier(artifact domain.RawArtifact, policy domain.TrustPolicy) []string {
	if policy == domain.TrustPolicyPermissive {
		return nil
	}
	if strings.TrimSpace(artifact.SupplierIdentity) == "" {
		return nil
	}
	if strings.EqualFold(artifact.SupplierIdentity, artifact.ProductOwner) {
		return nil
	}
	for _, supplier := range artifact.TrustedSuppliers {
		if strings.EqualFold(artifact.SupplierIdentity, supplier) {
			return nil
		}
	}
	return []string{fmt.Sprintf("unknown supplier identity %q", artifact.SupplierIdentity)}
}

func enforceSignaturePolicy(status domain.TrustStatus, policy domain.TrustPolicy) error {
	if policy != domain.TrustPolicyStrict {
		return nil
	}
	if status == domain.TrustStatusUnsigned {
		return fmt.Errorf("unsigned artifacts are rejected under strict policy")
	}
	return nil
}
