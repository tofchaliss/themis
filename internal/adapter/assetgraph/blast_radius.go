package assetgraph

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/themis-project/themis/internal/domain"
)

const blastRadiusMaxDepth = domain.BlastRadiusTraversalDepth

// MaxBlastRadiusDepth is the recursive CTE depth limit for blast-radius traversal.
const MaxBlastRadiusDepth = blastRadiusMaxDepth

func (s *PostgresStore) ComputeBlastRadius(ctx context.Context, finding domain.EnrichmentFinding) (domain.BlastRadiusResult, error) {
	if finding.ProductID == "" || finding.VulnerabilityID == "" || finding.ComponentID == "" {
		return domain.BlastRadiusResult{Score: domain.RiskScoreBlastRadiusMin}, nil
	}
	active, err := s.sbomActive(ctx, finding.SBOMDocumentID)
	if err != nil {
		return domain.BlastRadiusResult{}, err
	}
	if !active {
		return domain.BlastRadiusResult{Score: domain.RiskScoreBlastRadiusMin}, nil
	}
	if err := s.syncFindingGraph(ctx, finding); err != nil {
		return domain.BlastRadiusResult{}, err
	}
	customers, err := s.customersFromProduct(ctx, finding.ProductID)
	if err != nil {
		return domain.BlastRadiusResult{}, err
	}
	return domain.BlastRadiusResult{
		Score:       domain.ComputeBlastRadiusScore(len(customers)),
		CustomerIDs: customers,
	}, nil
}

// ProductBlastRadius returns blast-radius for a product without syncing finding graph links.
func (s *PostgresStore) ProductBlastRadius(ctx context.Context, productID, _, _ string) (domain.BlastRadiusResult, error) {
	if productID == "" {
		return domain.BlastRadiusResult{Score: domain.RiskScoreBlastRadiusMin}, nil
	}
	customers, err := s.customersFromProduct(ctx, productID)
	if err != nil {
		return domain.BlastRadiusResult{}, err
	}
	return domain.BlastRadiusResult{
		Score:       domain.ComputeBlastRadiusScore(len(customers)),
		CustomerIDs: customers,
	}, nil
}

// Enrich implements Layer2Enricher for sync enrichment.
func (s *PostgresStore) Enrich(ctx context.Context, finding domain.EnrichmentFinding) (domain.BlastRadiusResult, error) {
	return s.ComputeBlastRadius(ctx, finding)
}

func (s *PostgresStore) sbomActive(ctx context.Context, sbomDocumentID string) (bool, error) {
	if sbomDocumentID == "" {
		return true, nil
	}
	var deleted bool
	err := s.pool.QueryRow(ctx, `
		SELECT deleted_at IS NOT NULL FROM sbom_documents WHERE id = $1
	`, sbomDocumentID).Scan(&deleted)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("lookup sbom active state: %w", err)
	}
	return !deleted, nil
}

func (s *PostgresStore) syncFindingGraph(ctx context.Context, finding domain.EnrichmentFinding) error {
	if _, err := s.ensureNode(ctx, domain.GraphNodeTypeCVE, finding.VulnerabilityID); err != nil {
		return err
	}
	if _, err := s.ensureNode(ctx, domain.GraphNodeTypePackage, finding.ComponentID); err != nil {
		return err
	}
	if _, err := s.ensureNode(ctx, domain.GraphNodeTypeProduct, finding.ProductID); err != nil {
		return err
	}
	cveNodeID, err := s.nodeID(ctx, domain.GraphNodeTypeCVE, finding.VulnerabilityID)
	if err != nil {
		return err
	}
	packageNodeID, err := s.nodeID(ctx, domain.GraphNodeTypePackage, finding.ComponentID)
	if err != nil {
		return err
	}
	productNodeID, err := s.nodeID(ctx, domain.GraphNodeTypeProduct, finding.ProductID)
	if err != nil {
		return err
	}
	if err := s.ensureEdge(ctx, cveNodeID, packageNodeID, domain.GraphEdgeTypeCVEPackage); err != nil {
		return err
	}
	return s.ensureEdge(ctx, packageNodeID, productNodeID, domain.GraphEdgeTypePackageProduct)
}

func (s *PostgresStore) customersFromProduct(ctx context.Context, productID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		WITH RECURSIVE blast AS (
			SELECT n.id, n.node_type, n.entity_id, 0 AS depth
			FROM asset_graph_nodes n
			WHERE n.node_type = $2 AND n.entity_id = $1::uuid
			UNION ALL
			SELECT n2.id, n2.node_type, n2.entity_id, b.depth + 1
			FROM blast b
			JOIN asset_graph_edges e ON e.from_node_id = b.id
			JOIN asset_graph_nodes n2 ON n2.id = e.to_node_id
			WHERE b.depth < $3
		)
		SELECT DISTINCT entity_id::text
		FROM blast
		WHERE node_type = $4
		ORDER BY 1
	`, productID, domain.GraphNodeTypeProduct, domain.BlastRadiusTraversalDepth, domain.GraphNodeTypeCustomer)
	if err != nil {
		return nil, fmt.Errorf("blast-radius traversal: %w", err)
	}
	defer rows.Close()

	var customers []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		customers = append(customers, id)
	}
	return customers, rows.Err()
}
