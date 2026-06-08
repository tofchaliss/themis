package parser

import (
	"context"
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

func TestRegistryPort(t *testing.T) {
	port := RegistryPort{Registry: NewRegistry(RegistryConfig{})}
	outcome := port.Parse(context.Background(), domain.SBOMFormatCycloneDX, "1.4", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","components":[{"purl":"pkg:npm/a@1"}]}`))
	if !outcome.Accepted {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestRegistryPortNilRegistry(t *testing.T) {
	outcome := (RegistryPort{}).Parse(context.Background(), domain.SBOMFormatCycloneDX, "1.4", nil)
	if outcome.Accepted {
		t.Fatal("expected failure")
	}
}
