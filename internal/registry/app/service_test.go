package app_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
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

	// Name indexes standing in for the store's unique indexes (EDR-INTAKE-01 B4): products
	// fold case, projects fold case within their product, versions are matched exactly.
	productIDs map[string]string
	projectIDs map[string]string
	releaseIDs map[string]string
	rows       int

	errProductExists      error
	errProjectExists      error
	errReleaseExists      error
	errUpsertProduct      error
	errUpsertProject      error
	errUpsertRelease      error
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
		productIDs: map[string]string{}, projectIDs: map[string]string{}, releaseIDs: map[string]string{},
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

// The three find-or-creates. The ids they hand back are the ROW's ("row-1", …), never the
// service's IDGenerator's: identity belongs to the row that won the insert (B4), and using a
// visibly different vocabulary here is what makes a test asserting the wrong one fail.
func (r *fakeRepo) UpsertProduct(_ context.Context, name string) (string, bool, error) {
	id, created, err := r.findOrCreate(r.productIDs, strings.ToLower(name), r.errUpsertProduct)
	if created {
		r.products[id] = true
	}
	return id, created, err
}

func (r *fakeRepo) UpsertProject(_ context.Context, productID, name string) (string, bool, error) {
	id, created, err := r.findOrCreate(r.projectIDs, productID+"\x00"+strings.ToLower(name), r.errUpsertProject)
	if created {
		r.projects[id] = true
	}
	return id, created, err
}

func (r *fakeRepo) UpsertRelease(_ context.Context, projectID, version string) (string, bool, error) {
	// No ToLower: release uniqueness is exact on (project_id, version).
	id, created, err := r.findOrCreate(r.releaseIDs, projectID+"\x00"+version, r.errUpsertRelease)
	if created {
		rel, rerr := domain.NewRelease(domain.ReleaseID(id), domain.ProjectID(projectID), version)
		if rerr != nil {
			return "", false, rerr
		}
		r.releases[id] = rel
	}
	return id, created, err
}

func (r *fakeRepo) findOrCreate(index map[string]string, key string, injected error) (string, bool, error) {
	if injected != nil {
		return "", false, injected
	}
	if id, ok := index[key]; ok {
		return id, false, nil
	}
	r.rows++
	id := fmt.Sprintf("row-%d", r.rows)
	index[key] = id
	return id, true, nil
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
	return fmt.Sprintf("id-%d", s.n)
}

func newService(repo app.Repository) *app.RegistryService {
	return app.NewRegistryService(repo, &seqIDs{})
}

func TestRegisterProduct(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newService(repo)

	id, created, err := svc.RegisterProduct(ctx, "Themis")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	// The id is the STORE's, not the service IDGenerator's: the row that won the insert owns
	// identity (B4).
	if id != "row-1" || !created || !repo.products["row-1"] {
		t.Errorf("product not created: id=%q created=%v", id, created)
	}

	// Invalid name → domain error, nothing stored.
	if _, _, err := newService(newFakeRepo()).RegisterProduct(ctx, "  "); err == nil {
		t.Error("empty name: expected error")
	}
	// Store failure surfaces.
	failing := newFakeRepo()
	failing.errUpsertProduct = errors.New("boom")
	if _, _, err := newService(failing).RegisterProduct(ctx, "Themis"); err == nil {
		t.Error("upsert error: expected error")
	}
}

// B4 at the app layer: the same name twice is ONE Product, and the second caller is told it
// did not create it. Case folds for a human-typed name (the store's index is on lower(name)),
// so "themis" finds "Themis" — and the first caller's casing is what stays.
func TestRegisterProductFindOrCreateReportsCreated(t *testing.T) {
	ctx := context.Background()
	svc := newService(newFakeRepo())

	first, created, err := svc.RegisterProduct(ctx, "Themis")
	if err != nil || !created {
		t.Fatalf("first register = %q created=%v err=%v, want created", first, created, err)
	}
	second, created, err := svc.RegisterProduct(ctx, "themis")
	if err != nil {
		t.Fatalf("second register: %v", err)
	}
	if created {
		t.Error("created=true on a name that already existed — a duplicate must not fork a Product")
	}
	if second != first {
		t.Errorf("second register id = %q, want the existing %q", second, first)
	}
}

func TestRegisterProject(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	repo.products["prod-1"] = true
	svc := newService(repo)

	id, created, err := svc.RegisterProject(ctx, "prod-1", "api")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if id != "row-1" || !created {
		t.Errorf("project = %q created=%v, want row-1 created", id, created)
	}

	// Unknown product.
	if _, _, err := newService(newFakeRepo()).RegisterProject(ctx, "nope", "api"); !errors.Is(err, app.ErrUnknownProduct) {
		t.Errorf("unknown product: err = %v, want ErrUnknownProduct", err)
	}
	// ProductExists error.
	pe := newFakeRepo()
	pe.errProductExists = errors.New("db down")
	if _, _, err := newService(pe).RegisterProject(ctx, "prod-1", "api"); err == nil {
		t.Error("ProductExists error: expected error")
	}
	// Invalid name (product exists).
	if _, _, err := svc.RegisterProject(ctx, "prod-1", " "); err == nil {
		t.Error("empty name: expected error")
	}
	// Store failure.
	sf := newFakeRepo()
	sf.products["prod-1"] = true
	sf.errUpsertProject = errors.New("boom")
	if _, _, err := newService(sf).RegisterProject(ctx, "prod-1", "api"); err == nil {
		t.Error("upsert error: expected error")
	}
}

// The existence pre-check is the only thing that can NAME the missing parent: the product_id
// foreign key refuses an unknown parent with a constraint violation, which does not tell a
// caller which part of its request missed. B4 moved UNIQUENESS to the database; it did not
// move this, and a find-or-create that answered "constraint 23503" would be a regression.
func TestRegisterProjectUnknownProductStillNamed(t *testing.T) {
	_, created, err := newService(newFakeRepo()).RegisterProject(context.Background(), "prod-ghost", "api")
	if !errors.Is(err, app.ErrUnknownProduct) {
		t.Fatalf("err = %v, want ErrUnknownProduct", err)
	}
	if created {
		t.Error("a refused registration reported created=true")
	}
	if !strings.Contains(err.Error(), "prod-ghost") {
		t.Errorf("error %q does not name the missing product", err)
	}
}

func TestRegisterRelease(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	repo.projects["proj-1"] = true
	svc := newService(repo)

	id, created, err := svc.RegisterRelease(ctx, "proj-1", "1.2.3")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if id != "row-1" || !created {
		t.Errorf("release = %q created=%v, want row-1 created", id, created)
	}

	// Unknown project.
	if _, _, err := newService(newFakeRepo()).RegisterRelease(ctx, "nope", "1.0"); !errors.Is(err, app.ErrUnknownProject) {
		t.Errorf("unknown project: err = %v, want ErrUnknownProject", err)
	}
	// ProjectExists error.
	pe := newFakeRepo()
	pe.errProjectExists = errors.New("db down")
	if _, _, err := newService(pe).RegisterRelease(ctx, "proj-1", "1.0"); err == nil {
		t.Error("ProjectExists error: expected error")
	}
	// Invalid version.
	if _, _, err := svc.RegisterRelease(ctx, "proj-1", "  "); err == nil {
		t.Error("empty version: expected error")
	}
	// Store failure.
	sf := newFakeRepo()
	sf.projects["proj-1"] = true
	sf.errUpsertRelease = errors.New("boom")
	if _, _, err := newService(sf).RegisterRelease(ctx, "proj-1", "1.0"); err == nil {
		t.Error("upsert error: expected error")
	}
}

// Re-registering a version is the SAME Release, answered idempotently — two bots building one
// version at the same moment is the normal case (B4). Version matching is EXACT, so a
// differently-cased build string is a different Release and must still be created.
func TestRegisterReleaseFindOrCreateReportsCreated(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	repo.projects["proj-1"] = true
	svc := newService(repo)

	first, created, err := svc.RegisterRelease(ctx, "proj-1", "R1917.256")
	if err != nil || !created {
		t.Fatalf("first register = %q created=%v err=%v, want created", first, created, err)
	}
	second, created, err := svc.RegisterRelease(ctx, "proj-1", "R1917.256")
	if err != nil {
		t.Fatalf("second register: %v", err)
	}
	if created || second != first {
		t.Errorf("second register = %q created=%v, want %q created=false", second, created, first)
	}

	other, created, err := svc.RegisterRelease(ctx, "proj-1", "r1917.256")
	if err != nil || !created {
		t.Fatalf("lower-cased version = %q created=%v err=%v, want a NEW release", other, created, err)
	}
	if other == first {
		t.Error("a differently-cased version collapsed into one Release — folding a build string merges two builds")
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
