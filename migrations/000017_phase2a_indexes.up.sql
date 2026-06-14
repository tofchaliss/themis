CREATE INDEX idx_risk_context_epss_kev ON risk_context (epss_score, kev_listed);
CREATE INDEX idx_asset_graph_edges_from_type ON asset_graph_edges (from_node_id, edge_type);
