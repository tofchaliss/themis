# Notification Service Specification

## Purpose
Deliver routed and aggregated vulnerability notifications over SMTP and Microsoft Teams.

## Requirements

### Requirement: Email notification delivery via SMTP
The system SHALL deliver notifications via SMTP to configured recipients. SMTP credentials SHALL be loaded from environment variables only — never from config files or CLI arguments. TLS (STARTTLS or direct TLS) SHALL be required.

#### Scenario: Email sent on scan completion
- **WHEN** an ingestion reaches `COMPLETED` status and a notification rule matches
- **THEN** the system SHALL send an email to the configured recipient(s) with the scan summary, product name, vulnerability counts by severity, and a link to the scan

#### Scenario: SMTP credentials not logged
- **WHEN** Themis starts or connects to the SMTP server
- **THEN** the SMTP password SHALL never appear in application logs at any log level

#### Scenario: SMTP failure retried
- **WHEN** an SMTP connection fails or times out
- **THEN** the system SHALL retry with exponential backoff up to a configurable maximum (default: 3 retries), then mark the notification as failed and log an error

---

### Requirement: Microsoft Teams notification via incoming webhook
The system SHALL deliver notifications to Microsoft Teams channels via Teams incoming webhook URLs. Webhook URLs SHALL be loaded from environment variables or a secrets provider.

#### Scenario: Teams notification sent on new CVE watch finding
- **WHEN** a CVE watch job creates a new finding at or above the product's notification severity threshold
- **THEN** the system SHALL POST a formatted Teams Adaptive Card message to the configured webhook URL including CVE ID, affected component, severity, product name, and effective state

#### Scenario: Teams webhook URL not logged
- **WHEN** Themis delivers a Teams notification
- **THEN** the Teams webhook URL SHALL never appear in application logs at any log level

#### Scenario: Teams delivery failure logged
- **WHEN** a Teams webhook POST returns a non-2xx response
- **THEN** the system SHALL log the failure with the HTTP status code (not the webhook URL), mark the notification as failed, and retry up to the configured maximum

---

### Requirement: Configurable notification routing rules
The system SHALL support routing rules that govern which events trigger notifications, to which channels, for which products/projects, and at what severity threshold. Rules SHALL be manageable via REST API.

#### Scenario: Routing rule by severity threshold
- **WHEN** a routing rule specifies `min_severity=high`
- **THEN** the system SHALL only send notifications for findings with `raw_severity` of `HIGH` or `CRITICAL`

#### Scenario: Routing rule by event type
- **WHEN** a routing rule specifies `event_types=[ingestion_completed, cve_watch_finding]`
- **THEN** the system SHALL send notifications for those event types only and suppress others

#### Scenario: Routing rule scoped to product
- **WHEN** a routing rule specifies `product_id=<id>`
- **THEN** the system SHALL send notifications only for events belonging to that product

#### Scenario: Routing rules managed via API
- **WHEN** a caller PUTs `/api/v1/config/notifications`
- **THEN** the system SHALL replace the existing routing rules with the provided configuration and validate the schema before persisting

---

### Requirement: Notification event types
The system SHALL support the following notification trigger events: `ingestion_completed`, `ingestion_rejected`, `cve_watch_finding`, `triage_decision`, `vex_updated`.

#### Scenario: Triage decision notification sent
- **WHEN** a human L4 triage decision is recorded
- **THEN** the system SHALL evaluate routing rules for `triage_decision` event type and deliver notifications to matching channels

#### Scenario: VEX update notification sent
- **WHEN** a new VEX document is ingested and changes effective states of one or more findings
- **THEN** the system SHALL evaluate routing rules for `vex_updated` and deliver a digest notification listing the affected (component, CVE) pairs

---

### Requirement: Notification digest for bulk events
The system SHALL aggregate multiple findings from the same CVE watch cycle or ingestion into a single digest notification rather than sending one notification per finding, to prevent notification fatigue.

#### Scenario: Bulk CVE watch findings aggregated
- **WHEN** a CVE watch cycle creates 20 new findings for Product A
- **THEN** the system SHALL send one digest notification per channel listing all 20 findings, not 20 individual notifications

#### Scenario: Digest includes severity breakdown
- **WHEN** a digest notification is sent
- **THEN** it SHALL include a count of findings by severity (critical: N, high: N, medium: N)

---

### Requirement: Notification configuration API
The system SHALL expose `GET /api/v1/config/notifications` and `PUT /api/v1/config/notifications` for reading and updating routing rules. Only admin-scoped API keys SHALL be permitted to modify notification configuration.

#### Scenario: Notification config readable
- **WHEN** a caller with any valid API key queries `GET /api/v1/config/notifications`
- **THEN** the system SHALL return the current routing rules (webhook URLs redacted)

#### Scenario: Notification config update requires admin key
- **WHEN** a caller with a read-only API key attempts `PUT /api/v1/config/notifications`
- **THEN** the system SHALL return HTTP 403

#### Scenario: Webhook URLs redacted in API response
- **WHEN** notification config is returned via the API
- **THEN** Teams webhook URLs SHALL be masked (e.g., `https://outlook.office.com/webhook/****`) in the response body

---

### Requirement: Notification delivery observability
The system SHALL emit Prometheus metrics for notification delivery, including success count, failure count, and latency per channel type (email, teams).

#### Scenario: Delivery metrics emitted
- **WHEN** a notification is delivered or fails
- **THEN** the system SHALL increment `themis_notifications_total` with labels `channel_type` and `status` (success | failure | retried)
