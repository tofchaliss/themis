## ADDED Requirements

### Requirement: Default project auto-created on product registration
The system SHALL auto-create a default project when a product is registered, so that every
product has a project able to parent versions without a separate manual call.

#### Scenario: Product registration creates a default project
- **WHEN** a caller posts to `POST /api/v1/products`
- **THEN** the system SHALL create the product and a default project linked to it, and the
  product's versions MAY be created under that project without an explicit project creation

#### Scenario: Default project is reused, not duplicated
- **WHEN** a product already has its auto-created default project
- **THEN** subsequent operations on that product SHALL reuse the existing default project and
  SHALL NOT create additional default projects

### Requirement: Version registration endpoint
The system SHALL provide `POST /api/v1/projects/{id}/versions` to create a version under a
project. The created `versions` row SHALL reference the project via `project_id` (NOT NULL).

#### Scenario: Version created under a project
- **WHEN** a caller posts to `POST /api/v1/projects/{id}/versions` with a version name for a
  valid project
- **THEN** the system SHALL create a `versions` record with `project_id` set to that project
  and return its `id` and `version`

#### Scenario: Duplicate version under the same project rejected
- **WHEN** a caller posts a version name that already exists for the project
- **THEN** the system SHALL NOT create a duplicate and SHALL return a conflict error

#### Scenario: Version for non-existent project → 404
- **WHEN** `POST /api/v1/projects/{id}/versions` is called for a project that does not exist
- **THEN** the system SHALL return `404` with error code `PROJECT_NOT_FOUND`

### Requirement: Artifact registration endpoint
The system SHALL provide `POST /api/v1/products/{id}/artifacts` to register an artifact
(identified by its `image_digest`) before SBOM upload, replacing the prior requirement to
insert image rows via direct SQL. The artifact SHALL be linked to a version under the product.

#### Scenario: Artifact registered with a digest
- **WHEN** a caller posts to `POST /api/v1/products/{id}/artifacts` with an `image_digest` and
  target version for a valid product
- **THEN** the system SHALL create an `artifacts` record carrying that `image_digest` and
  return its `id`

#### Scenario: Duplicate digest maps to the same artifact
- **WHEN** an artifact is registered with an `image_digest` that already exists
- **THEN** the system SHALL NOT create a second artifact row (digest is globally unique) and
  SHALL return the existing artifact identity

#### Scenario: SBOM upload references a registered artifact
- **WHEN** an SBOM is uploaded for a digest that has been registered via the artifact endpoint
- **THEN** the ingestion integrity check SHALL resolve the artifact without requiring a manual
  `images` insert
