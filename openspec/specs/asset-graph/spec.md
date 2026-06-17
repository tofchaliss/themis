# asset-graph Specification

## Purpose
TBD - created by archiving change themis-phase-2a. Update Purpose after archive.
## Requirements
### Requirement: Microservice registration
The system SHALL allow explicit registration of Microservices within a Product via
`POST /api/v1/products/{id}/microservices`. A Microservice represents a named
service within a Product that has its own security boundary and team ownership.

#### Scenario: Microservice created under a product
- **WHEN** `POST /api/v1/products/{id}/microservices` is called with a valid
  `name`, optional `description`, and optional `tech_stack` JSON
- **THEN** the system SHALL create a `microservices` row and a corresponding
  `asset_graph_nodes` row with `node_type = Microservice`, and return `201 Created`
  with the new microservice ID

#### Scenario: Duplicate microservice name within a product → 409
- **WHEN** a Microservice with the same `name` already exists under the same
  `product_id`
- **THEN** the system SHALL return `409` with error code `DUPLICATE_MICROSERVICE`

#### Scenario: Microservice not found product → 404
- **WHEN** the `product_id` in the path does not exist
- **THEN** the system SHALL return `404` with error code `PRODUCT_NOT_FOUND`

---

### Requirement: Deployment registration
The system SHALL allow explicit registration of Deployments for a Microservice
via `POST /api/v1/microservices/{id}/deployments`. A Deployment represents a
running instance of a Microservice in a specific environment owned by a Customer.

#### Scenario: Deployment created under a microservice
- **WHEN** `POST /api/v1/microservices/{id}/deployments` is called with a valid
  `environment`, `region`, and `customer_id`
- **THEN** the system SHALL create a `deployments` row and graph edges linking
  Microservice → Deployment → Customer in `asset_graph_edges`, and return
  `201 Created` with the new deployment ID

#### Scenario: Deployment with unknown customer_id → 404
- **WHEN** the `customer_id` in the request body references a non-existent Customer
- **THEN** the system SHALL return `404` with error code `CUSTOMER_NOT_FOUND`

---

### Requirement: Customer registration
The system SHALL allow registration of Customers (internal teams or owners) via
`POST /api/v1/customers`. A Customer is the internal organisational unit that
owns Deployments and receives security notifications.

#### Scenario: Customer created
- **WHEN** `POST /api/v1/customers` is called with a valid `name`,
  `contact_email`, and optional `notification_preferences`
- **THEN** the system SHALL create a `customers` row and a corresponding
  `asset_graph_nodes` row with `node_type = Customer`, and return `201 Created`

#### Scenario: Duplicate customer email → 409
- **WHEN** a Customer with the same `contact_email` already exists
- **THEN** the system SHALL return `409` with error code `DUPLICATE_CUSTOMER`

---

### Requirement: Asset graph node and edge integrity
All Microservice, Deployment, and Customer registrations SHALL create corresponding
nodes in `asset_graph_nodes` and edges in `asset_graph_edges`. Graph edges SHALL
be consistent with the relational hierarchy: Product → Microservice → Deployment →
Customer. Orphaned nodes (nodes with no edges) are valid (a Microservice registered
before any Deployments is orphaned by design).

#### Scenario: Graph edge created on Deployment registration
- **WHEN** a Deployment is registered under a Microservice linked to a Customer
- **THEN** `asset_graph_edges` SHALL contain edges for
  `(Microservice → Deployment)` and `(Deployment → Customer)` with
  appropriate `edge_type` values

#### Scenario: Blast-radius traversal finds Customer nodes via graph
- **WHEN** Layer 2 traverses the graph for a CVE affecting a Package linked
  to a Product that has Microservices with Deployments owned by Customers
- **THEN** the recursive CTE traversal SHALL return all reachable Customer IDs
  within depth ≤ 7

