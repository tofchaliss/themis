package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/registry/domain"
)

func TestNewProduct(t *testing.T) {
	p, err := domain.NewProduct("prod-1", "  Themis  ")
	if err != nil {
		t.Fatalf("valid product: %v", err)
	}
	if p.ID() != "prod-1" {
		t.Errorf("ID = %q, want prod-1", p.ID())
	}
	if p.Name() != "Themis" {
		t.Errorf("Name = %q, want trimmed Themis", p.Name())
	}

	for name, tc := range map[string]struct {
		id    domain.ProductID
		pname string
	}{
		"emptyID":   {"", "Themis"},
		"emptyName": {"prod-1", "   "},
	} {
		if _, err := domain.NewProduct(tc.id, tc.pname); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestNewProject(t *testing.T) {
	p, err := domain.NewProject("proj-1", "prod-1", "api")
	if err != nil {
		t.Fatalf("valid project: %v", err)
	}
	if p.ID() != "proj-1" || p.ProductID() != "prod-1" || p.Name() != "api" {
		t.Errorf("project = %+v", p)
	}

	// Every Project must belong to exactly one Product.
	for name, tc := range map[string]struct {
		id      domain.ProjectID
		product domain.ProductID
		pname   string
	}{
		"emptyID":      {"", "prod-1", "api"},
		"emptyProduct": {"proj-1", "", "api"},
		"emptyName":    {"proj-1", "prod-1", " "},
	} {
		if _, err := domain.NewProject(tc.id, tc.product, tc.pname); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestNewCustomer(t *testing.T) {
	c, err := domain.NewCustomer("cust-1", "  Acme  ")
	if err != nil {
		t.Fatalf("valid customer: %v", err)
	}
	if c.ID() != "cust-1" || c.Name() != "Acme" {
		t.Errorf("customer = %+v", c)
	}
	for name, tc := range map[string]struct {
		id    domain.CustomerID
		cname string
	}{
		"emptyID":   {"", "Acme"},
		"emptyName": {"cust-1", "  "},
	} {
		if _, err := domain.NewCustomer(tc.id, tc.cname); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestNewMicroservice(t *testing.T) {
	m, err := domain.NewMicroservice("ms-1", "prod-1", "  payments  ")
	if err != nil {
		t.Fatalf("valid microservice: %v", err)
	}
	if m.ID() != "ms-1" || m.ProductID() != "prod-1" || m.Name() != "payments" {
		t.Errorf("microservice = %+v", m)
	}
	for name, tc := range map[string]struct {
		id      domain.MicroserviceID
		product domain.ProductID
		mname   string
	}{
		"emptyID":      {"", "prod-1", "payments"},
		"emptyProduct": {"ms-1", "", "payments"},
		"emptyName":    {"ms-1", "prod-1", " "},
	} {
		if _, err := domain.NewMicroservice(tc.id, tc.product, tc.mname); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestNewDeployment(t *testing.T) {
	d, err := domain.NewDeployment("dep-1", "ms-1", "cust-1", "  prod  ")
	if err != nil {
		t.Fatalf("valid deployment: %v", err)
	}
	if d.ID() != "dep-1" || d.MicroserviceID() != "ms-1" || d.CustomerID() != "cust-1" || d.Environment() != "prod" {
		t.Errorf("deployment = %+v", d)
	}
	for name, tc := range map[string]struct {
		id           domain.DeploymentID
		microservice domain.MicroserviceID
		customer     domain.CustomerID
		env          string
	}{
		"emptyID":           {"", "ms-1", "cust-1", "prod"},
		"emptyMicroservice": {"dep-1", "", "cust-1", "prod"},
		"emptyCustomer":     {"dep-1", "ms-1", "", "prod"},
		"emptyEnv":          {"dep-1", "ms-1", "cust-1", " "},
	} {
		if _, err := domain.NewDeployment(tc.id, tc.microservice, tc.customer, tc.env); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestNewRelease(t *testing.T) {
	r, err := domain.NewRelease("rel-1", "proj-1", "  1.2.3  ")
	if err != nil {
		t.Fatalf("valid release: %v", err)
	}
	if r.ID() != "rel-1" || r.ProjectID() != "proj-1" || r.Version() != "1.2.3" {
		t.Errorf("release = %+v (version %q)", r, r.Version())
	}

	// Every Release must belong to exactly one Project and carry a version.
	for name, tc := range map[string]struct {
		id      domain.ReleaseID
		project domain.ProjectID
		version string
	}{
		"emptyID":      {"", "proj-1", "1.0"},
		"emptyProject": {"rel-1", "", "1.0"},
		"emptyVersion": {"rel-1", "proj-1", "  "},
	} {
		if _, err := domain.NewRelease(tc.id, tc.project, tc.version); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
