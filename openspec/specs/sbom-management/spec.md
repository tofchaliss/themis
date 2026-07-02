# sbom-management Specification

## Purpose
TBD - created by archiving change themis-phase-2a. Update Purpose after archive.
## Requirements
### Requirement: SBOM list endpoints
The system SHALL provide paginated SBOM listing at two scopes:
`GET /api/v1/sboms` (system-wide) and `GET /api/v1/products/{id}/sboms`
(product-scoped). Both endpoints use cursor-based pagination consistent with
existing list endpoints. Deleted SBOMs (non-null `deleted_at`) SHALL be excluded.
Each listed entry represents an artifact's latest scan; the `is_latest` indicator
SHALL be derived from `scan_reports.scanned_at DESC` rather than stored as a flag.

#### Scenario: System-wide SBOM list returns paginated results
- **WHEN** `GET /api/v1/sboms` is called
- **THEN** the response SHALL include a `sboms` array where each entry has
  `id`, `product_name`, `product_version`, `image_name`, `image_digest`,
  `format`, `component_count`, `vulnerability_count`, `uploaded_at`, and
  `is_latest` (derived from the most recent `scan_reports` row); plus
  `next_cursor` (null if last page) and `total`

#### Scenario: Product-scoped SBOM list filters by product
- **WHEN** `GET /api/v1/products/{id}/sboms` is called for a valid product
- **THEN** the response SHALL include only SBOMs belonging to that product

#### Scenario: Deleted SBOMs absent from listing
- **WHEN** one or more SBOMs have been soft-deleted
- **THEN** neither `GET /api/v1/sboms` nor `GET /api/v1/products/{id}/sboms`
  SHALL include those SBOMs in their results

#### Scenario: Product not found → 404
- **WHEN** `GET /api/v1/products/{id}/sboms` is called for a non-existent product
- **THEN** the system SHALL return `404` with error code `PRODUCT_NOT_FOUND`

### Requirement: SBOM soft-delete
The system SHALL allow deletion of a specific SBOM via
`DELETE /api/v1/sboms/{id}`. Deletion is a soft-delete: the system sets the
record's `deleted_at = NOW()`. Data is never hard-deleted via API.
Deleting the latest scan for an artifact requires `?force=true`, where "latest"
is determined by `scan_reports.scanned_at DESC` (not an `is_latest` flag). Every
deletion SHALL write an entry to `audit_log`.

#### Scenario: Soft-delete sets deleted_at
- **WHEN** `DELETE /api/v1/sboms/{id}` is called for a scan that is not the latest
  for its artifact
- **THEN** `deleted_at` SHALL be set to the current timestamp;
  the SBOM SHALL no longer appear in listing or status queries; the response
  SHALL include a summary of archived component and finding counts

#### Scenario: Deleting the latest scan without force=true → 409
- **WHEN** `DELETE /api/v1/sboms/{id}` is called for the most recent `scan_reports`
  row of an artifact and `?force=true` is absent from the request
- **THEN** the system SHALL return `409` with error code
  `CANNOT_DELETE_LATEST_SBOM`

#### Scenario: Deleting the latest scan with force=true succeeds
- **WHEN** `DELETE /api/v1/sboms/{id}?force=true` is called for the most recent
  `scan_reports` row of an artifact
- **THEN** `deleted_at` SHALL be set and the deletion SHALL
  proceed; the response SHALL confirm the archived summary

#### Scenario: Audit log entry written on deletion
- **WHEN** a soft-delete succeeds (with or without force)
- **THEN** the system SHALL write an `audit_log` entry recording the deleted SBOM
  id, actor, and timestamp

