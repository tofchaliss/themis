// Package serializer is the Communication context's outbound serializer registry (D7): the
// mirror of Evidence's inbound parser ACL. Each artifact type is rendered into concrete
// bytes by a format serializer (CycloneDX VEX / OpenVEX / CSAF / human-readable advisory /
// audit report / channel-native notification); the registry is extensible (adding a format
// is one localized change), and the external format shapes never leak into the domain — a
// serializer only reads the abstract domain.Artifact.
package serializer

import (
	"errors"
	"sort"

	"github.com/themis-project/themis/internal/communication/domain"
)

// ErrUnknownFormat is returned when no serializer is registered for a requested format.
var ErrUnknownFormat = errors.New("communication: unknown serializer format")

// Serializer renders an abstract artifact into concrete bytes for one format.
type Serializer interface {
	// Format is the stable format identifier (e.g. "openvex", "cyclonedx-vex", "csaf").
	Format() string
	// Render deterministically serializes the artifact; re-rendering the same artifact
	// yields identical bytes (D1 regenerability).
	Render(art domain.Artifact) ([]byte, error)
}

// Registry resolves a format to its serializer.
type Registry struct {
	byFormat map[string]Serializer
}

// NewRegistry builds a registry over the given serializers (last wins on a format clash).
func NewRegistry(serializers ...Serializer) *Registry {
	r := &Registry{byFormat: make(map[string]Serializer, len(serializers))}
	for _, s := range serializers {
		r.byFormat[s.Format()] = s
	}
	return r
}

// Default builds the registry with all built-in serializers (standards-first).
func Default() *Registry {
	return NewRegistry(OpenVEX{}, CycloneDXVEX{}, CSAF{}, MarkdownAdvisory{}, JSONReport{}, TextNotification{})
}

// Render serializes the artifact in the requested format, or ErrUnknownFormat if none is
// registered.
func (r *Registry) Render(format string, art domain.Artifact) ([]byte, error) {
	s, ok := r.byFormat[format]
	if !ok {
		return nil, ErrUnknownFormat
	}
	return s.Render(art)
}

// Formats lists the registered format identifiers, sorted.
func (r *Registry) Formats() []string {
	out := make([]string, 0, len(r.byFormat))
	for f := range r.byFormat {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}
