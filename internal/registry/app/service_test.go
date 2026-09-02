package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/registry/app"
	"github.com/themis-project/themis/internal/registry/domain"
)

// fakeRepo is an in-memory Repository with error-injection hooks for the failure paths.
type fakeRepo struct {
	products      map[string]bool
	projects      map[string]bool
	releases      map[string]domain.Release
	projectObjs   map[string]domain.Project
	productObjs   map[string]domain.Product
	microservices map[string]bool
	customers     map[string]bool

	errProductExists      error
	errProjectExists      error
	errReleaseExists      error
	errSaveProduct        error
	errSaveProject        error
	errSaveRelease        error
	errGetRelease         error
	errList               error
	errMicroserviceExists error
	errCustomerExists     error
	errSaveMicroservice   error
	errSaveCustomer       error
	errSaveDeployment     error
	blast                 int
	errBlast              error
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		products: map[string]bool{}, projects: map[string]bool{}, releases: map[string]domain.Release{},
		microservices: map[string]bool{}, customers: map[string]bool{},
	}
}

func (r *fakeRepo) SaveCustomer(_ context.Context, c domain.Customer) error {
	if r.errSaveCustomer != nil {
		return r.errSaveCustomer
	}
	r.customers[string(c.ID())] = true
	return nil
}

func (r *fakeRepo) SaveMicroservice(_ context.Context, m domain.Microservice) error {
	if r.errSaveMicroservice != nil {
		return r.errSaveMicroservice
	}
	r.microservices[string(m.ID())] = true
	return nil
}

func (r *fakeRepo) SaveDeployment(_ context.Context, _ domain.Deployment) error {
	return r.errSaveDeployment
}

func (r *fakeRepo) MicroserviceExists(_ context.Context, id string) (bool, error) {
	return r.microservices[id], r.errMicroserviceExists
}

func (r *fakeRepo) CustomerExists(_ context.Context, id string) (bool, error) {
	return r.customers[id], r.errCustomerExists
}

func (r *fakeRepo) BlastRadiusCustomers(_ context.Context, _ string) (int, error) {
	return r.blast, r.errBlast
}

func (r *fakeRepo) SaveProduct(_ context.Context, p domain.Product) error {
	if r.errSaveProduct != nil {
		return r.errSaveProduct
	}
	r.products[string(p.ID())] = true
	return nil
}

func (r *fakeRepo) SaveProject(_ context.Context, p domain.Project) error {
	if r.errSaveProject != nil {
		return r.errSaveProject
	}
	r.projects[string(p.ID())] = true
	return nil
}

func (r *fakeRepo) SaveRelease(_ context.Context, rel domain.Release) error {
	if r.errSaveRelease != nil {
		return r.errSaveRelease
	}
	r.releases[string(rel.ID())] = rel
	return nil
}

func (r *fakeRepo) GetRelease(_ context.Context, id domain.ReleaseID) (domain.Release, error) {
	if r.errGetRelease != nil {
		return domain.Release{}, r.errGetRelease
	}
	return r.releases[string(id)], nil
}

func (r *fakeRepo) GetProject(_ context.Context, id domain.ProjectID) (domain.Project, error) {
	p, ok := r.projectObjs[string(id)]
	if !ok {
		return domain.Project{}, errors.New("not found")
	}
	return p, nil
}

func (r *fakeRepo) GetProduct(_ context.Context, id domain.ProductID) (domain.Product, error) {
	p, ok := r.productObjs[string(id)]
	if !ok {
		return domain.Product{}, errors.New("not found")
	}
	return p, nil
}

func (r *fakeRepo) ListProducts(_ context.Context, name string) ([]domain.Product, error) {
	if r.errList != nil {
		return nil, r.errList
	}
	out := make([]domain.Product, 0, len(r.products))
	for id := range r.products {
		p, err := domain.NewProduct(domain.ProductID(id), "product-"+id)
		if err != nil {
			return nil, err
		}
		if name != "" && p.Name() != name {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

func (r *fakeRepo) ListProjects(_ context.Context, product domain.ProductID, name string) ([]domain.Project, error) {
	if r.errList != nil {
		return nil, r.errList
	}
	out := make([]domain.Project, 0, len(r.projects))
	for id := range r.projects {
		p, err := domain.NewProject(domain.ProjectID(id), product, "project-"+id)
		if err != nil {
			return nil, err
		}
		if name != "" && p.Name() != name {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

func (r *fakeRepo) ListReleases(_ context.Context, _ domain.ProjectID) ([]domain.Release, error) {
	if r.errList != nil {
		return nil, r.errList
	}
	out := make([]domain.Release, 0, len(r.releases))
	for _, rel := range r.releases {
		out = append(out, rel)
	}
	return out, nil
}

func (r *fakeRepo) ProductExists(_ context.Context, id string) (bool, error) {
	return r.products[id], r.errProductExists
}
func (r *fakeRepo) ProjectExists(_ context.Context, id string) (bool, error) {
	return r.projects[id], r.errProjectExists
}
func (r *fakeRepo) ReleaseExists(_ context.Context, id string) (bool, error) {
	_, ok := r.releases[id]
	return ok, r.errReleaseExists
}

// seqIDs yields deterministic ids for assertions.
type seqIDs struct{ n int }

func (s *seqIDs) NewID() string {
	s.n++
	return map[int]string{1: "id-1", 2: "id-2", 3: "id-3"}[s.n]
}

func newService(repo app.Repository) *app.RegistryService {
	return app.NewRegistryService(repo, &seqIDs{})
}

func TestRegisterProduct(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newService(repo)

	id, err := svc.RegisterProduct(ctx, "Themis")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if id != "id-1" || !repo.products["id-1"] {
		t.Errorf("product not saved: id=%q", id)
	}

	// Invalid name → domain error, nothing saved.
	if _, err := newService(newFakeRepo()).RegisterProduct(ctx, "  "); err == nil {
		t.Error("empty name: expected error")
	}
	// Save failure surfaces.
	failing := newFakeRepo()
	failing.errSaveProduct = errors.New("boom")
	if _, err := newService(failing).RegisterProduct(ctx, "Themis"); err == nil {
		t.Error("save error: expected error")
	}
}

func TestRegisterProject(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	repo.products["prod-1"] = true
	svc := newService(repo)

	id, err := svc.RegisterProject(ctx, "prod-1", "api")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if id != "id-1" {
		t.Errorf("project id = %q, want id-1", id)
	}

	// Unknown product.
	if _, err := newService(newFakeRepo()).RegisterProject(ctx, "nope", "api"); !errors.Is(err, app.ErrUnknownProduct) {
		t.Errorf("unknown product: err = %v, want ErrUnknownProduct", err)
	}
	// ProductExists error.
	pe := newFakeRepo()
	pe.errProductExists = errors.New("db down")
	if _, err := newService(pe).RegisterProject(ctx, "prod-1", "api"); err == nil {
		t.Error("ProductExists error: expected error")
	}
	// Invalid name (product exists).
	if _, err := svc.RegisterProject(ctx, "prod-1", " "); err == nil {
		t.Error("empty name: expected error")
	}
	// Save failure.
	sf := newFakeRepo()
	sf.products["prod-1"] = true
	sf.errSaveProject = errors.New("boom")
	if _, err := newService(sf).RegisterProject(ctx, "prod-1", "api"); err == nil {
		t.Error("save error: expected error")
	}
}

func TestRegisterRelease(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	repo.projects["proj-1"] = true
	svc := newService(repo)

	id, err := svc.RegisterRelease(ctx, "proj-1", "1.2.3")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if id != "id-1" {
		t.Errorf("release id = %q, want id-1", id)
	}

	// Unknown project.
	if _, err := newService(newFakeRepo()).RegisterRelease(ctx, "nope", "1.0"); !errors.Is(err, app.ErrUnknownProject) {
		t.Errorf("unknown project: err = %v, want ErrUnknownProject", err)
	}
	// ProjectExists error.
	pe := newFakeRepo()
	pe.errProjectExists = errors.New("db down")
	if _, err := newService(pe).RegisterRelease(ctx, "proj-1", "1.0"); err == nil {
		t.Error("ProjectExists error: expected error")
	}
	// Invalid version.
	if _, err := svc.RegisterRelease(ctx, "proj-1", "  "); err == nil {
		t.Error("empty version: expected error")
	}
	// Save failure.
	sf := newFakeRepo()
	sf.projects["proj-1"] = true
	sf.errSaveRelease = errors.New("boom")
	if _, err := newService(sf).RegisterRelease(ctx, "proj-1", "1.0"); err == nil {
		t.Error("save error: expected error")
	}
}

func TestReadPaths(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	rel, _ := domain.NewRelease("rel-1", "proj-1", "1.0")
	repo.releases["rel-1"] = rel
	// The project must exist: ListReleases now distinguishes "this project has no releases" from
	// "there is no such project", and collapsing them sends a caller hunting for a typo in the
	// wrong place (DASH-1).
	repo.projects["proj-1"] = true
	svc := newService(repo)

	if ok, err := svc.ReleaseExists(ctx, "rel-1"); err != nil || !ok {
		t.Errorf("ReleaseExists(rel-1) = %v,%v want true,nil", ok, err)
	}
	if ok, _ := svc.ReleaseExists(ctx, "missing"); ok {
		t.Error("ReleaseExists(missing) = true, want false")
	}
	got, err := svc.GetRelease(ctx, "rel-1")
	if err != nil || got.ID() != "rel-1" {
		t.Errorf("GetRelease = %+v, %v", got, err)
	}
	list, err := svc.ListReleases(ctx, "proj-1")
	if err != nil || len(list) != 1 {
		t.Errorf("ListReleases = %+v, %v", list, err)
	}
	if _, err := svc.ListReleases(ctx, "no-such-project"); !errors.Is(err, app.ErrUnknownProject) {
		t.Errorf("ListReleases(unknown) = %v, want ErrUnknownProject — an empty list would read as 'no releases'", err)
	}
}

func TestRegisterCustomer(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	id, err := newService(repo).RegisterCustomer(ctx, "Acme")
	if err != nil || id != "id-1" || !repo.customers["id-1"] {
		t.Fatalf("register customer: id=%q err=%v", id, err)
	}
	if _, err := newService(newFakeRepo()).RegisterCustomer(ctx, " "); err == nil {
		t.Error("empty name: expected error")
	}
	failing := newFakeRepo()
	failing.errSaveCustomer = errors.New("boom")
	if _, err := newService(failing).RegisterCustomer(ctx, "Acme"); err == nil {
		t.Error("save error: expected error")
	}
}

func TestRegisterMicroservice(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	repo.products["prod-1"] = true
	id, err := newService(repo).RegisterMicroservice(ctx, "prod-1", "payments")
	if err != nil || id != "id-1" {
		t.Fatalf("register ms: id=%q err=%v", id, err)
	}
	if _, err := newService(newFakeRepo()).RegisterMicroservice(ctx, "nope", "payments"); !errors.Is(err, app.ErrUnknownProduct) {
		t.Errorf("unknown product: %v", err)
	}
	pe := newFakeRepo()
	pe.errProductExists = errors.New("db down")
	if _, err := newService(pe).RegisterMicroservice(ctx, "prod-1", "payments"); err == nil {
		t.Error("ProductExists error: expected error")
	}
	inv := newFakeRepo()
	inv.products["prod-1"] = true
	if _, err := newService(inv).RegisterMicroservice(ctx, "prod-1", " "); err == nil {
		t.Error("empty name: expected error")
	}
	sf := newFakeRepo()
	sf.products["prod-1"] = true
	sf.errSaveMicroservice = errors.New("boom")
	if _, err := newService(sf).RegisterMicroservice(ctx, "prod-1", "payments"); err == nil {
		t.Error("save error: expected error")
	}
}

func TestRegisterDeployment(t *testing.T) {
	ctx := context.Background()
	base := func() *fakeRepo {
		r := newFakeRepo()
		r.microservices["ms-1"] = true
		r.customers["cust-1"] = true
		return r
	}
	id, err := newService(base()).RegisterDeployment(ctx, "ms-1", "cust-1", "prod")
	if err != nil || id != "id-1" {
		t.Fatalf("register deployment: id=%q err=%v", id, err)
	}
	if _, err := newService(newFakeRepo()).RegisterDeployment(ctx, "nope", "cust-1", "prod"); !errors.Is(err, app.ErrUnknownMicroservice) {
		t.Errorf("unknown ms: %v", err)
	}
	me := base()
	me.errMicroserviceExists = errors.New("db down")
	if _, err := newService(me).RegisterDeployment(ctx, "ms-1", "cust-1", "prod"); err == nil {
		t.Error("MicroserviceExists error: expected error")
	}
	noCust := newFakeRepo()
	noCust.microservices["ms-1"] = true
	if _, err := newService(noCust).RegisterDeployment(ctx, "ms-1", "nope", "prod"); !errors.Is(err, app.ErrUnknownCustomer) {
		t.Errorf("unknown customer: %v", err)
	}
	ce := base()
	ce.errCustomerExists = errors.New("db down")
	if _, err := newService(ce).RegisterDeployment(ctx, "ms-1", "cust-1", "prod"); err == nil {
		t.Error("CustomerExists error: expected error")
	}
	if _, err := newService(base()).RegisterDeployment(ctx, "ms-1", "cust-1", " "); err == nil {
		t.Error("empty env: expected error")
	}
	sf := base()
	sf.errSaveDeployment = errors.New("boom")
	if _, err := newService(sf).RegisterDeployment(ctx, "ms-1", "cust-1", "prod"); err == nil {
		t.Error("save error: expected error")
	}
}

func TestBlastRadius(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	repo.blast = 7
	if n, err := newService(repo).BlastRadius(ctx, "rel-1"); err != nil || n != 7 {
		t.Errorf("blast = %d, %v, want 7,nil", n, err)
	}
	be := newFakeRepo()
	be.errBlast = errors.New("db down")
	if _, err := newService(be).BlastRadius(ctx, "rel-1"); err == nil {
		t.Error("blast error: expected error")
	}
}

// DASH-1 at the app layer: "this parent has no children" and "there is no such parent" are
// different answers, and collapsing them sends a caller hunting for a typo in the wrong place.
func TestListProductsAndProjects(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	repo.products["prod-1"] = true
	repo.projects["proj-1"] = true
	svc := newService(repo)

	if got, err := svc.ListProducts(ctx, ""); err != nil || len(got) != 1 {
		t.Errorf("ListProducts = %+v, %v", got, err)
	}
	if got, err := svc.ListProjects(ctx, "prod-1", ""); err != nil || len(got) != 1 {
		t.Errorf("ListProjects = %+v, %v", got, err)
	}
	if _, err := svc.ListProjects(ctx, "no-such-product", ""); !errors.Is(err, app.ErrUnknownProduct) {
		t.Errorf("ListProjects(unknown) = %v, want ErrUnknownProduct", err)
	}

	// An EXISTENCE-check failure must surface too: a read error there is not "no such product",
	// and answering 404 on a database blip would send someone looking for a typo that is not there.
	boom := newFakeRepo()
	boom.errProductExists = errors.New("db down")
	if _, err := newService(boom).ListProjects(ctx, "prod-1", ""); err == nil {
		t.Error("a ProductExists failure must surface from ListProjects")
	}
	boom2 := newFakeRepo()
	boom2.errProjectExists = errors.New("db down")
	if _, err := newService(boom2).ListReleases(ctx, "proj-1"); err == nil {
		t.Error("a ProjectExists failure must surface from ListReleases")
	}

	// A store failure must surface rather than read as "you have none".
	failing := newFakeRepo()
	failing.products["prod-1"] = true
	failing.errList = errors.New("db down")
	if _, err := newService(failing).ListProducts(ctx, ""); err == nil {
		t.Error("a store failure must surface from ListProducts")
	}
	if _, err := newService(failing).ListProjects(ctx, "prod-1", ""); err == nil {
		t.Error("a store failure must surface from ListProjects")
	}
}

// The upward name-chain passthroughs (D13.4).
func TestGetProjectAndProductPassthrough(t *testing.T) {
	repo := newFakeRepo()
	proj, _ := domain.NewProject("proj-1", "prod-1", "cdmrf-oamp")
	prod, _ := domain.NewProduct("prod-1", "MRF")
	repo.projectObjs = map[string]domain.Project{"proj-1": proj}
	repo.productObjs = map[string]domain.Product{"prod-1": prod}
	svc := newService(repo)
	if got, err := svc.GetProject(context.Background(), "proj-1"); err != nil || got.Name() != "cdmrf-oamp" {
		t.Errorf("GetProject = %v %v", got, err)
	}
	if got, err := svc.GetProduct(context.Background(), "prod-1"); err != nil || got.Name() != "MRF" {
		t.Errorf("GetProduct = %v %v", got, err)
	}
	if _, err := svc.GetProject(context.Background(), "ghost"); err == nil {
		t.Error("unknown project must error")
	}
	if _, err := svc.GetProduct(context.Background(), "ghost"); err == nil {
		t.Error("unknown product must error")
	}
}
