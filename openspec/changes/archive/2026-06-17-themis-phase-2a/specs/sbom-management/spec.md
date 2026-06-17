## ADDED Requirements

### Requirement: SBOM list endpoints
The system SHALL provide paginated SBOM listing at two scopes:
`GET /api/v1/sboms` (system-wide) and `GET /api/v1/products/{id}/sboms`
(product-scoped). Both endpoints use cursor-based pagination consistent with
existing list endpoints. Deleted SBOMs (non-null `deleted_at`) SHALL be excluded.

#### Scenario: System-wide SBOM list returns paginated results
- **WHEN** `GET /api/v1/sboms` is called
- **THEN** the response SHALL include a `sboms` array where each entry has
  `id`, `product_name`, `product_version`, `image_name`, `image_digest`,
  `format`, `component_count`, `vulnerability_count`, `uploaded_at`, and
  `is_latest`; plus `next_cursor` (null if last page) and `total`

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

---

### Requirement: SBOM soft-delete
The system SHALL allow deletion of a specific SBOM via
`DELETE /api/v1/sboms/{id}`. Deletion is a soft-delete: the system sets
`sbom_documents.deleted_at = NOW()`. Data is never hard-deleted via API.
Deleting the most recent SBOM for a product requires `?force=true`. Every
deletion SHALL write an entry to `audit_log`.

#### Scenario: Soft-delete sets deleted_at
- **WHEN** `DELETE /api/v1/sboms/{id}` is called for a non-latest SBOM
- **THEN** `sbom_documents.deleted_at` SHALL be set to the current timestamp;
  the SBOM SHALL no longer appear in listing or status queries; the response
  SHALL include a summary of archived component and finding counts

#### Scenario: Deleting the latest SBOM without force=true → 409
- **WHEN** `DELETE /api/v1/sboms/{id}` is called for an SBOM with `is_latest = true`
  and `?force=true` is absent from the request
- **THEN** the system SHALL return `409` with error code
  `CANNOT_DELETE_LATEST_SBOM`

#### Scenario: Deleting the latest SBOM with force=true succeeds
- **WHEN** `DELETE /api/v1/sboms/{id}?force=true` is called for an SBOM with
  `is_latest = true`
- **THEN** `sbom_documents.deleted_at` SHALL be set and the deletion SHALL
  proceed; the response SHALL confirm the archived summary

#### Scenario: Audit log entry written on deletion
- **WHEN** a soft-delete succeeds (with or without force)
- **THEN** the system SHALL write an `audit_log` row with the API key ID,
  timestamp, action `SBOM_DELETED`, and the `sbom_id`

#### Scenario: All active queries exclude deleted SBOMs
- **WHEN** any store-layer query for component, finding, or product data runs
- **THEN** it SHALL apply `WHERE sbom_documents.deleted_at IS NULL` at the
  store layer and SHALL NOT require callers to add this filter explicitly

#### Scenario: SBOM not found → 404
- **WHEN** `DELETE /api/v1/sboms/{id}` is called for an ID that does not exist
  or has already been deleted
- **THEN** the system SHALL return `404` with error code `SBOM_NOT_FOUND`
