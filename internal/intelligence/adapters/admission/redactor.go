// Package admission holds the Intelligence Gateway's pre-invocation admission adapters
// (Δ2 C7): a secret/PII Redactor mirroring Communication's redaction discipline. The
// full data-classification → provider-clearance machinery is deferred to when cloud
// providers exist (G-AI-5); Δ2 is local-only, so redaction is defense-in-depth.
package admission

import (
	"regexp"
	"strconv"
	"strings"
)

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
	// purl is a package URL — an IDENTIFIER, never PII. See Redact for why it is protected.
	purl = regexp.MustCompile(`pkg:[^\s"',)\]]+`)
)

// purlSentinel brackets a protected purl while the PII patterns run. It uses Unicode
// private-use characters so it cannot collide with anything in a prompt built from package
// metadata, CVE text or vendor advisories.
const purlSentinel = ""

// Redact returns text with recognized secrets/PII masked.
//
// PURLs are protected from the PII patterns first, and that is a correctness fix, not a
// convenience. A purl is `pkg:type/namespace/name@version`, and a module-stream RPM version ends
// in a letter suffix — `javapackages-filesystem@5.3.0-2.module+el8.3.0+125+5da1ae29`. The email
// pattern reads that as local-part `javapackages-filesystem`, domain `5.3.0-2`, TLD `module`, and
// masks the package name out of the middle of its own identifier.
//
// Measured on a live estate 2026-08-09: EVERY `recommend_position` invocation on a module-stream
// component was refused with `business_invalid`, and the failure was invisible in the only way
// that matters — it surfaced as "the AI declined". Two distinct harms, and the second is worse:
//
//  1. The model cites the mangled purl, Grounding Verification correctly rejects it, and the
//     recommendation is discarded.
//  2. The model never learns WHICH package it is assessing. Redaction is supposed to protect
//     against leaking data to a provider; here it silently removed the subject of the question.
//
// The trade recorded honestly: a secret embedded INSIDE a purl is no longer masked. A purl is a
// package coordinate — type, namespace, name, version, qualifiers — and credentials do not live
// there, so the exposure is theoretical while the breakage was total.
func (BasicRedactor) Redact(text string) string {
	var saved []string
	out := purl.ReplaceAllStringFunc(text, func(m string) string {
		saved = append(saved, m)
		return purlSentinel + strconv.Itoa(len(saved)-1) + purlSentinel
	})
	out = secretKV.ReplaceAllString(out, "$1=[REDACTED]")
	out = email.ReplaceAllString(out, "[REDACTED]")
	for i, m := range saved {
		out = strings.ReplaceAll(out, purlSentinel+strconv.Itoa(i)+purlSentinel, m)
	}
	return out
}
