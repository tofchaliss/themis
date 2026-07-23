package main

// Accepted enum values mirrored from the Themis API. The MCP server is kept
// decoupled from the core module, so these are hand-mirrored rather than
// imported — the drift guard in enums_test.go asserts they stay in lockstep
// with the generated types in internal/adapter/api/gen.
var (
	sbomFormats          = []string{"cyclonedx", "spdx"}
	triageDecisions      = []string{"false_positive", "accepted_risk", "confirmed", "resolved", "escalate"}
	notificationChannels = []string{"email", "slack", "webhook"}
)

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}
