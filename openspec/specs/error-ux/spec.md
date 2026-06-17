# error-ux Specification

## Purpose
TBD - created by archiving change themis-phase-2a. Update Purpose after archive.
## Requirements
### Requirement: Three-field error envelope on all endpoints
Every error response from any API endpoint SHALL use the following JSON envelope:

```json
{
  "error": {
    "code":    "<SCREAMING_SNAKE_CASE>",
    "message": "<plain English explanation>",
    "hint":    "<actionable next step>"
  }
}
```

This requirement applies to all existing and new endpoints, not only the endpoints
added in Phase 2a. No raw database errors, Go error strings, constraint violation
names, or stack traces SHALL appear in any response body.

#### Scenario: 404 response uses envelope format
- **WHEN** any API endpoint returns a 404 status
- **THEN** the response body SHALL be `{"error": {"code": "<code>", "message": "...",
  "hint": "..."}}`; the `code` field SHALL be one of the defined catalogue codes

#### Scenario: No raw database error string in response
- **WHEN** a database error occurs during request handling (e.g. unique constraint
  violation, connection timeout)
- **THEN** the system SHALL map the error to a catalogue code and return the
  envelope format; the raw PostgreSQL error string SHALL NOT appear in the
  response body

#### Scenario: 500 response uses INTERNAL_ERROR code
- **WHEN** an unhandled error occurs that does not match any catalogue code
- **THEN** the system SHALL return `500` with `code = INTERNAL_ERROR`,
  `message = "Something went wrong on our end. The problem has been logged."`,
  and `hint = "If this keeps happening, check the Themis server logs for details."`

---

### Requirement: Error catalogue coverage
The system SHALL implement the following error codes and responses. Every code
SHALL map to exactly one HTTP status.

| Code | HTTP | Applies to |
| --- | --- | --- |
| `SBOM_NOT_FOUND` | 404 | DELETE /api/v1/sboms/{id}, GET paths with SBOM ID |
| `PRODUCT_NOT_FOUND` | 404 | Any endpoint with a product ID path parameter |
| `IMAGE_NOT_FOUND` | 404 | Any endpoint referencing an image that is not registered |
| `CUSTOMER_NOT_FOUND` | 404 | Deployment registration with unknown customer_id |
| `CANNOT_DELETE_LATEST_SBOM` | 409 | DELETE /api/v1/sboms/{id} without force=true |
| `DUPLICATE_MICROSERVICE` | 409 | POST /api/v1/products/{id}/microservices with duplicate name |
| `DUPLICATE_CUSTOMER` | 409 | POST /api/v1/customers with duplicate email |
| `INVALID_SBOM_FORMAT` | 422 | SBOM upload when format is invalid or required field is missing |
| `INVALID_REQUEST` | 400 | Any request with an invalid or missing required parameter |
| `MISSING_API_KEY` | 401 | Any request without the `X-API-Key` header |
| `INVALID_API_KEY` | 401 | Any request with an unrecognised or revoked API key |
| `INTERNAL_ERROR` | 500 | Any unhandled internal error |

#### Scenario: SBOM_NOT_FOUND returned with actionable hint
- **WHEN** `DELETE /api/v1/sboms/{id}` is called with a non-existent ID
- **THEN** the response SHALL have HTTP 404 and `code = SBOM_NOT_FOUND`,
  `message` explaining the SBOM was not found or was already deleted, and
  `hint` directing the caller to use `GET /api/v1/sboms` to list available SBOMs

#### Scenario: CANNOT_DELETE_LATEST_SBOM hint explains force=true option
- **WHEN** `DELETE /api/v1/sboms/{id}` is called on the latest SBOM without force
- **THEN** the response SHALL have HTTP 409 and `hint` explaining the `?force=true`
  option and the recommendation to upload a newer SBOM first

#### Scenario: Messages use plain English without technical jargon
- **WHEN** any error response is generated
- **THEN** `message` SHALL use natural language ("couldn't find", "removed",
  "invalid format") and SHALL NOT contain Go error strings, SQL error codes,
  HTTP status numbers, or internal field names

