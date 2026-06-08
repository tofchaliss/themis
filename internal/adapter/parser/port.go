package parser

import (
	"context"

	"github.com/themis-project/themis/internal/domain"
)

// RegistryPort adapts Registry to domain.SBOMParserPort.
type RegistryPort struct {
	Registry *Registry
}

// Parse normalizes a raw SBOM document.
func (p RegistryPort) Parse(ctx context.Context, format, specVersion string, raw []byte) domain.ParseOutcome {
	if p.Registry == nil {
		return domain.ParseOutcome{
			Accepted:   false,
			HTTPStatus: 500,
			Status:     domain.ParseStatusFailed,
			Message:    "parser registry unavailable",
		}
	}
	return p.Registry.Parse(ctx, format, specVersion, raw)
}
