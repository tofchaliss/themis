// Package parser is Evidence's border ACL (EDR-EVIDENCE-01 D4): it translates a raw
// SBOM in a supported standard format (CycloneDX or SPDX) into the context's
// canonical domain.Inventory. Standards only — scanners such as Trivy are producers
// of these standards, not formats of their own, so they must export a standard.
// Format-specific decoding never leaks past this package.
package parser

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/themis-project/themis/internal/evidence/domain"
)

// Format identifies a supported SBOM standard.
type Format string

const (
	FormatCycloneDX Format = "cyclonedx"
	FormatSPDX      Format = "spdx"
)

const defaultMaxComponents = 50_000

// Result is a successful translation: the canonical inventory plus any non-fatal
// warnings (e.g. components skipped for lacking a usable purl).
type Result struct {
	Inventory domain.Inventory
	Warnings  []string
}

// UnsupportedFormatError is the helpful rejection returned for an unknown format.
type UnsupportedFormatError struct {
	Requested string
	Supported []Format
}

func (e *UnsupportedFormatError) Error() string {
	names := make([]string, len(e.Supported))
	for i, f := range e.Supported {
		names[i] = string(f)
	}
	return fmt.Sprintf("unsupported SBOM format %q; supported: %s", e.Requested, strings.Join(names, ", "))
}

// formatParser translates one raw format into components + edges + warnings.
type formatParser interface {
	parse(raw []byte, specVersion string) (components []domain.Component, edges []domain.DependencyEdge, warnings []string, err error)
}

// Registry selects a format parser and enforces limits. It is the reusable,
// extensible ACL: adding a standard is one new formatParser + registry entry.
type Registry struct {
	parsers       map[Format]formatParser
	maxComponents int
}

// Option configures a Registry.
type Option func(*Registry)

// WithMaxComponents caps the number of components an SBOM may contain.
func WithMaxComponents(n int) Option {
	return func(r *Registry) {
		if n > 0 {
			r.maxComponents = n
		}
	}
}

// NewRegistry builds the default registry (CycloneDX + SPDX).
func NewRegistry(opts ...Option) *Registry {
	r := &Registry{
		parsers: map[Format]formatParser{
			FormatCycloneDX: cycloneDXParser{},
			FormatSPDX:      spdxParser{},
		},
		maxComponents: defaultMaxComponents,
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Supported lists the registered formats, sorted for stable messages.
func (r *Registry) Supported() []Format {
	out := make([]Format, 0, len(r.parsers))
	for f := range r.parsers {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Parse translates raw bytes of the named format into a canonical Inventory. An
// unknown format yields an *UnsupportedFormatError (a helpful rejection).
func (r *Registry) Parse(ctx context.Context, format, specVersion string, raw []byte) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	p, ok := r.parsers[Format(format)]
	if !ok {
		return Result{}, &UnsupportedFormatError{Requested: format, Supported: r.Supported()}
	}
	components, edges, warnings, err := p.parse(raw, specVersion)
	if err != nil {
		return Result{}, err
	}
	if len(components) > r.maxComponents {
		return Result{}, fmt.Errorf("component count %d exceeds maximum %d", len(components), r.maxComponents)
	}
	return Result{Inventory: domain.NewInventory(components, edges), Warnings: warnings}, nil
}
