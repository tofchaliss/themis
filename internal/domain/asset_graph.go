package domain

import "time"

// Graph node types stored in asset_graph_nodes.
const (
	GraphNodeTypeCVE          = "CVE"
	GraphNodeTypeCWE          = "CWE"
	GraphNodeTypePackage      = "Package"
	GraphNodeTypeProduct      = "Product"
	GraphNodeTypeMicroservice = "Microservice"
	GraphNodeTypeDeployment   = "Deployment"
	GraphNodeTypeCustomer     = "Customer"
)

// Graph edge types linking asset graph nodes.
const (
	GraphEdgeTypeProductMicroservice = "product_microservice"
	GraphEdgeTypeMicroserviceDeploy  = "microservice_deployment"
	GraphEdgeTypeDeploymentCustomer  = "deployment_customer"
	GraphEdgeTypePackageProduct      = "package_product"
	GraphEdgeTypeCVEPackage          = "cve_package"
)

// Microservice is a named service within a product security boundary.
type Microservice struct {
	ID          string
	ProductID   string
	Name        string
	Description string
	TechStack   map[string]string
	CreatedAt   time.Time
}

// Deployment is a running instance of a microservice owned by a customer team.
type Deployment struct {
	ID             string
	MicroserviceID string
	CustomerID     string
	Environment    string
	Region         string
	CreatedAt      time.Time
}

// Customer is an internal team or owner that receives security notifications.
type Customer struct {
	ID                      string
	Name                    string
	ContactEmail            string
	NotificationPreferences map[string]string
	CreatedAt               time.Time
}

// ExploitRecord is a public exploit entry from ExploitDB.
type ExploitRecord struct {
	ID            string
	EDBID         string
	CVEID         string
	ExploitType   string
	PublishedDate *time.Time
	Title         string
	CreatedAt     time.Time
}

// EPSSSignal is an EPSS probability score for a CVE.
type EPSSSignal struct {
	CVEID     string
	Score     float64
	FetchedAt time.Time
	Stale     bool
}

// KEVSignal records whether a CVE is on the CISA KEV list.
type KEVSignal struct {
	CVEID     string
	Listed    bool
	FetchedAt time.Time
	Stale     bool
}

// GraphNode is a node in the asset graph.
type GraphNode struct {
	ID         string
	NodeType   string
	EntityID   string
	Properties map[string]string
	CreatedAt  time.Time
}

// GraphEdge links two asset graph nodes.
type GraphEdge struct {
	ID         string
	FromNodeID string
	ToNodeID   string
	EdgeType   string
	Weight     float64
	CreatedAt  time.Time
}
