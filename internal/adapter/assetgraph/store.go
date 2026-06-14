package assetgraph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/themis-project/themis/internal/domain"
)

type pgPool interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// PostgresStore implements domain.GraphStore.
type PostgresStore struct {
	pool pgPool
}

// NewPostgresStore creates an asset graph store.
func NewPostgresStore(pool pgPool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) CreateMicroservice(ctx context.Context, ms domain.Microservice) (domain.Microservice, error) {
	if _, err := s.productExists(ctx, ms.ProductID); err != nil {
		return domain.Microservice{}, err
	}
	if ms.ID == "" {
		ms.ID = uuid.NewString()
	}
	techStack, err := json.Marshal(ms.TechStack)
	if err != nil {
		return domain.Microservice{}, fmt.Errorf("encode tech_stack: %w", err)
	}
	err = s.pool.QueryRow(ctx, `
		INSERT INTO microservices (id, product_id, name, description, tech_stack)
		VALUES ($1, $2, $3, NULLIF($4, ''), $5)
		RETURNING created_at
	`, ms.ID, ms.ProductID, ms.Name, ms.Description, techStack).Scan(&ms.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return domain.Microservice{}, ErrDuplicateMicroservice
		}
		return domain.Microservice{}, fmt.Errorf("create microservice: %w", err)
	}
	productNodeID, err := s.ensureNode(ctx, domain.GraphNodeTypeProduct, ms.ProductID)
	if err != nil {
		return domain.Microservice{}, err
	}
	msNodeID, err := s.ensureNode(ctx, domain.GraphNodeTypeMicroservice, ms.ID)
	if err != nil {
		return domain.Microservice{}, err
	}
	if err := s.ensureEdge(ctx, productNodeID, msNodeID, domain.GraphEdgeTypeProductMicroservice); err != nil {
		return domain.Microservice{}, err
	}
	return ms, nil
}

func (s *PostgresStore) CreateCustomer(ctx context.Context, customer domain.Customer) (domain.Customer, error) {
	if customer.ID == "" {
		customer.ID = uuid.NewString()
	}
	prefs, err := json.Marshal(customer.NotificationPreferences)
	if err != nil {
		return domain.Customer{}, fmt.Errorf("encode notification_preferences: %w", err)
	}
	err = s.pool.QueryRow(ctx, `
		INSERT INTO customers (id, name, contact_email, notification_preferences)
		VALUES ($1, $2, $3, $4)
		RETURNING created_at
	`, customer.ID, customer.Name, customer.ContactEmail, prefs).Scan(&customer.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return domain.Customer{}, ErrDuplicateCustomer
		}
		return domain.Customer{}, fmt.Errorf("create customer: %w", err)
	}
	if _, err := s.ensureNode(ctx, domain.GraphNodeTypeCustomer, customer.ID); err != nil {
		return domain.Customer{}, err
	}
	return customer, nil
}

func (s *PostgresStore) CreateDeployment(ctx context.Context, dep domain.Deployment) (domain.Deployment, error) {
	ms, err := s.GetMicroservice(ctx, dep.MicroserviceID)
	if err != nil {
		return domain.Deployment{}, err
	}
	if _, err := s.GetCustomer(ctx, dep.CustomerID); err != nil {
		return domain.Deployment{}, err
	}
	if dep.ID == "" {
		dep.ID = uuid.NewString()
	}
	if dep.Region == "" {
		dep.Region = ""
	}
	err = s.pool.QueryRow(ctx, `
		INSERT INTO deployments (id, microservice_id, customer_id, environment, region)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING created_at
	`, dep.ID, dep.MicroserviceID, dep.CustomerID, dep.Environment, dep.Region).Scan(&dep.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return domain.Deployment{}, ErrDuplicateDeployment
		}
		return domain.Deployment{}, fmt.Errorf("create deployment: %w", err)
	}
	msNodeID, err := s.nodeID(ctx, domain.GraphNodeTypeMicroservice, ms.ID)
	if err != nil {
		return domain.Deployment{}, err
	}
	depNodeID, err := s.ensureNode(ctx, domain.GraphNodeTypeDeployment, dep.ID)
	if err != nil {
		return domain.Deployment{}, err
	}
	customerNodeID, err := s.nodeID(ctx, domain.GraphNodeTypeCustomer, dep.CustomerID)
	if err != nil {
		return domain.Deployment{}, err
	}
	if err := s.ensureEdge(ctx, msNodeID, depNodeID, domain.GraphEdgeTypeMicroserviceDeploy); err != nil {
		return domain.Deployment{}, err
	}
	if err := s.ensureEdge(ctx, depNodeID, customerNodeID, domain.GraphEdgeTypeDeploymentCustomer); err != nil {
		return domain.Deployment{}, err
	}
	return dep, nil
}

func (s *PostgresStore) GetMicroservice(ctx context.Context, id string) (domain.Microservice, error) {
	var (
		ms        domain.Microservice
		techStack []byte
	)
	err := s.pool.QueryRow(ctx, `
		SELECT id, product_id, name, COALESCE(description, ''), tech_stack, created_at
		FROM microservices WHERE id = $1
	`, id).Scan(&ms.ID, &ms.ProductID, &ms.Name, &ms.Description, &techStack, &ms.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return domain.Microservice{}, ErrMicroserviceNotFound
		}
		return domain.Microservice{}, fmt.Errorf("get microservice: %w", err)
	}
	if len(techStack) > 0 {
		_ = json.Unmarshal(techStack, &ms.TechStack)
	}
	if ms.TechStack == nil {
		ms.TechStack = map[string]string{}
	}
	return ms, nil
}

func (s *PostgresStore) GetCustomer(ctx context.Context, id string) (domain.Customer, error) {
	var (
		customer domain.Customer
		prefs    []byte
	)
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, contact_email, notification_preferences, created_at
		FROM customers WHERE id = $1
	`, id).Scan(&customer.ID, &customer.Name, &customer.ContactEmail, &prefs, &customer.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return domain.Customer{}, ErrCustomerNotFound
		}
		return domain.Customer{}, fmt.Errorf("get customer: %w", err)
	}
	if len(prefs) > 0 {
		_ = json.Unmarshal(prefs, &customer.NotificationPreferences)
	}
	if customer.NotificationPreferences == nil {
		customer.NotificationPreferences = map[string]string{}
	}
	return customer, nil
}

func (s *PostgresStore) productExists(ctx context.Context, productID string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM products WHERE id = $1)`, productID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("lookup product: %w", err)
	}
	if !exists {
		return false, ErrProductNotFound
	}
	return true, nil
}

func (s *PostgresStore) ensureNode(ctx context.Context, nodeType, entityID string) (string, error) {
	id := uuid.NewString()
	var nodeID string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO asset_graph_nodes (id, node_type, entity_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (node_type, entity_id) DO UPDATE SET entity_id = EXCLUDED.entity_id
		RETURNING id
	`, id, nodeType, entityID).Scan(&nodeID)
	if err != nil {
		return "", fmt.Errorf("ensure graph node: %w", err)
	}
	return nodeID, nil
}

func (s *PostgresStore) nodeID(ctx context.Context, nodeType, entityID string) (string, error) {
	var nodeID string
	err := s.pool.QueryRow(ctx, `
		SELECT id FROM asset_graph_nodes WHERE node_type = $1 AND entity_id = $2
	`, nodeType, entityID).Scan(&nodeID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", fmt.Errorf("graph node missing for %s %s", nodeType, entityID)
		}
		return "", err
	}
	return nodeID, nil
}

func (s *PostgresStore) ensureEdge(ctx context.Context, fromID, toID, edgeType string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO asset_graph_edges (id, from_node_id, to_node_id, edge_type)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (from_node_id, to_node_id, edge_type) DO NOTHING
	`, uuid.NewString(), fromID, toID, edgeType)
	if err != nil {
		return fmt.Errorf("ensure graph edge: %w", err)
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
