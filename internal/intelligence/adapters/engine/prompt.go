package engine

import (
	_ "embed"
	"fmt"
	"strings"
	"text/template"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

//go:embed templates/recommend_position.tmpl
var recommendPositionTmpl string

// PromptRenderer builds provider-facing prompts from the assembled context (D6). The
// templates are Gateway-owned adapter assets — no prompt strings live in the domain
// or app rings. It implements app.PromptRenderer.
type PromptRenderer struct {
	templates map[string]*template.Template
}

// NewPromptRenderer builds the Δ1 renderer with the embedded recommend_position
// template.
func NewPromptRenderer() (*PromptRenderer, error) {
	return newRenderer(map[string]string{"recommend_position": recommendPositionTmpl})
}

// newRenderer parses the given capability-id -> template-text map (unexported so
// tests can inject templates, including malformed ones).
func newRenderer(src map[string]string) (*PromptRenderer, error) {
	tmpls := make(map[string]*template.Template, len(src))
	for id, text := range src {
		t, err := template.New(id).Parse(text)
		if err != nil {
			return nil, fmt.Errorf("parse prompt template %q: %w", id, err)
		}
		tmpls[id] = t
	}
	return &PromptRenderer{templates: tmpls}, nil
}

// Render renders the capability's prompt from the assembled context.
func (r *PromptRenderer) Render(capabilityID string, ctx domain.AssembledContext) (string, error) {
	t, ok := r.templates[capabilityID]
	if !ok {
		return "", fmt.Errorf("no prompt template for capability %q", capabilityID)
	}
	var sb strings.Builder
	if err := t.Execute(&sb, ctx); err != nil {
		return "", fmt.Errorf("render prompt %q: %w", capabilityID, err)
	}
	return sb.String(), nil
}
