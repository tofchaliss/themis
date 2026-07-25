// Package admission holds the Intelligence Gateway's pre-invocation admission adapters
// (Δ2 C7): a secret/PII Redactor mirroring Communication's redaction discipline. The
// full data-classification → provider-clearance machinery is deferred to when cloud
// providers exist (G-AI-5); Δ2 is local-only, so redaction is defense-in-depth.
package admission

import "regexp"

// BasicRedactor masks the most common secret/PII patterns in a prompt before it reaches a
// provider. It is conservative (mask, never drop), stateless, and implements app.Redactor.
type BasicRedactor struct{}

// NewBasicRedactor builds the default redactor.
func NewBasicRedactor() BasicRedactor { return BasicRedactor{} }

var (
	// key/value secrets: password=…, token: …, api_key …, authorization bearer …
	secretKV = regexp.MustCompile(`(?i)\b(password|passwd|token|secret|api[_-]?key|authorization|bearer)\b\s*[:=]?\s*\S+`)
	// email addresses (PII)
	email = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)
)

// Redact returns text with recognized secrets/PII masked.
func (BasicRedactor) Redact(text string) string {
	out := secretKV.ReplaceAllString(text, "$1=[REDACTED]")
	out = email.ReplaceAllString(out, "[REDACTED]")
	return out
}
