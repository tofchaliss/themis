package main

import (
	"testing"

	"github.com/themis-project/themis/internal/adapter/api/gen"
)

// TestEnumsMatchGeneratedAPI is a drift guard: the MCP server mirrors a few
// Themis API enums by hand (see enums.go) to stay decoupled from the core
// module. This test — exempt from the cmd depguard rule because it is a _test.go
// file — imports the generated types and fails if the server ever adds or
// renames a value, so the mirrored lists cannot silently fall out of sync.
func TestEnumsMatchGeneratedAPI(t *testing.T) {
	genFormats := []string{
		string(gen.SBOMUploadRequestFormatCyclonedx),
		string(gen.SBOMUploadRequestFormatSpdx),
	}
	assertSameSet(t, "sbom formats", sbomFormats, genFormats)

	genDecisions := []string{
		string(gen.FalsePositive),
		string(gen.AcceptedRisk),
		string(gen.Confirmed),
		string(gen.Resolved),
		string(gen.Escalate),
	}
	assertSameSet(t, "triage decisions", triageDecisions, genDecisions)

	genChannels := []string{
		string(gen.Email),
		string(gen.Slack),
		string(gen.Webhook),
	}
	assertSameSet(t, "notification channels", notificationChannels, genChannels)
}

func assertSameSet(t *testing.T, name string, mirrored, generated []string) {
	t.Helper()
	if len(mirrored) != len(generated) {
		t.Errorf("%s: mirrored has %d values %v but the API defines %d %v — update enums.go",
			name, len(mirrored), mirrored, len(generated), generated)
	}
	for _, v := range generated {
		if !contains(mirrored, v) {
			t.Errorf("%s: API value %q is missing from the mirrored list %v — update enums.go", name, v, mirrored)
		}
	}
	for _, v := range mirrored {
		if !contains(generated, v) {
			t.Errorf("%s: mirrored value %q is no longer in the API set %v — update enums.go", name, v, generated)
		}
	}
}
