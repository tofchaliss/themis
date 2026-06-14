package domain

import "context"

// Notification event types supported by the notification service.
const (
	NotificationEventIngestionCompleted = "ingestion_completed"
	NotificationEventIngestionRejected  = "ingestion_rejected"
	NotificationEventCVEWatchFinding    = "cve_watch_finding"
	NotificationEventTriageDecision     = "triage_decision"
	NotificationEventVEXUpdated         = "vex_updated"
	NotificationEventBlastRadiusTeam    = "blast_radius_team"
)

// Notification channel identifiers used in routing rules.
const (
	NotificationChannelEmail   = "email"
	NotificationChannelSlack   = "slack"
	NotificationChannelWebhook = "webhook"
)

// NotificationRuleFilter scopes routing rules to products and severities.
type NotificationRuleFilter struct {
	ProductID   string `json:"product_id,omitempty"`
	MinSeverity string `json:"min_severity,omitempty"`
}

// NotificationFinding is a single vulnerability finding included in a digest.
type NotificationFinding struct {
	CVEID          string
	ComponentPURL  string
	Severity       string
	EffectiveState string
}

// NotificationEvent is the payload evaluated by routing rules and delivered to channels.
type NotificationEvent struct {
	Type        string
	ProductID   string
	ProjectID   string
	ProductName string
	ScanID      string
	IngestionID string
	Message     string
	BatchKey    string
	Findings        []NotificationFinding
	CustomerID      string
	CVEID           string
	ComponentPURL   string
	BlastRadiusScore float64
}

// NotificationSender dispatches outbound notifications for domain events.
type NotificationSender interface {
	Dispatch(ctx context.Context, event NotificationEvent) error
	FlushDigest(ctx context.Context, batchKey string) error
}
