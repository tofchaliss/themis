package parser

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/themis-project/themis/internal/domain"
)

const (
	defaultMaxComponents = 50_000
	defaultParseTimeout  = 5 * time.Minute
)

// RegistryConfig configures parser limits.
type RegistryConfig struct {
	MaxComponents int
	ParseTimeout  time.Duration
}

// Registry selects format adapters and enforces parsing limits.
type Registry struct {
	adapters map[string]domain.SBOMAdapter
	config   RegistryConfig
}

// NewRegistry creates a registry with the default adapters and limits.
func NewRegistry(cfg RegistryConfig) *Registry {
	if cfg.MaxComponents <= 0 {
		cfg.MaxComponents = defaultMaxComponents
	}
	if cfg.ParseTimeout <= 0 {
		cfg.ParseTimeout = defaultParseTimeout
	}
	return &Registry{
		adapters: map[string]domain.SBOMAdapter{
			domain.SBOMFormatCycloneDX: CycloneDXAdapter{},
			domain.SBOMFormatSPDX:      SPDXAdapter{},
			domain.SBOMFormatTrivy:     TrivyAdapter{},
			domain.SBOMFormatGrype:     GrypeAdapter{},
			domain.SBOMFormatSyft:      SyftAdapter{},
		},
		config: cfg,
	}
}

// Parse normalizes a raw document using the adapter selected by format.
func (r *Registry) Parse(ctx context.Context, format, specVersion string, raw []byte) domain.ParseOutcome {
	adapter, ok := r.adapters[format]
	if !ok {
		supported := domain.SupportedSBOMFormats()
		return domain.ParseOutcome{
			Accepted:         false,
			HTTPStatus:       422,
			Status:           domain.ParseStatusRejected,
			Message:          fmt.Sprintf("unsupported format %q; supported formats: %s", format, stringsJoin(supported)),
			SupportedFormats: supported,
		}
	}

	parseCtx, cancel := context.WithTimeout(ctx, r.config.ParseTimeout)
	defer cancel()

	sbom, err := runAdapterParse(parseCtx, adapter, raw, specVersion)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(parseCtx.Err(), context.DeadlineExceeded) {
			return domain.ParseOutcome{
				Accepted:   false,
				HTTPStatus: 408,
				Status:     domain.ParseStatusFailed,
				Message:    fmt.Sprintf("parsing timed out after %s (document size %d bytes)", r.config.ParseTimeout, len(raw)),
			}
		}
		return domain.ParseOutcome{
			Accepted:   false,
			HTTPStatus: 422,
			Status:     domain.ParseStatusRejected,
			Message:    err.Error(),
		}
	}

	if len(sbom.Components) > r.config.MaxComponents {
		return domain.ParseOutcome{
			Accepted:   false,
			HTTPStatus: 422,
			Status:     domain.ParseStatusRejected,
			Message: fmt.Sprintf(
				"component count %d exceeds maximum %d",
				len(sbom.Components), r.config.MaxComponents,
			),
		}
	}

	sbom.Format = adapter.Format()
	if sbom.SpecVersion == "" {
		sbom.SpecVersion = specVersion
	}

	return domain.ParseOutcome{
		Accepted:   true,
		HTTPStatus: 200,
		Status:     domain.ParseStatusAccepted,
		SBOM:       sbom,
		Message:    "parsed",
	}
}

var runAdapterParse = func(ctx context.Context, adapter domain.SBOMAdapter, raw []byte, specVersion string) (domain.CanonicalSBOM, error) {
	type result struct {
		sbom domain.CanonicalSBOM
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		sbom, err := adapter.Parse(ctx, raw, specVersion)
		ch <- result{sbom: sbom, err: err}
	}()

	select {
	case <-ctx.Done():
		return domain.CanonicalSBOM{}, ctx.Err()
	case r := <-ch:
		return r.sbom, r.err
	}
}

func stringsJoin(items []string) string {
	if len(items) == 0 {
		return ""
	}
	out := items[0]
	for i := 1; i < len(items); i++ {
		out += ", " + items[i]
	}
	return out
}
