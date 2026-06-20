package watch_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/watch"
)

func TestRunCycleNVDSuccess(t *testing.T) {
	repo := &memoryWatchRepo{
		lastSuccess: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		catalog: []domain.WatchCatalogEntry{
			{ComponentVersionID: "cv-1", Name: "lodash", Ecosystem: "npm", Version: "4.17.20", ArtifactID: "sbom-1", ProductID: "prod-1"},
		},
	}
	metrics := &memoryMetrics{}
	var successTS time.Time
	svc := &watch.Service{
		NVD: &stubNVD{records: []domain.FeedVulnerability{
			{CVEID: "CVE-2021-23337", PackageName: "lodash", Ecosystem: "npm", Severity: "high", AffectedVersions: []string{"< 4.17.21"}},
		}},
		OSV:     &stubOSV{},
		Repo:    repo,
		Notify:  &recordingNotifier{},
		Metrics: metrics,
		Clock:   func() time.Time { return time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC) },
		OnSuccess: func(ts time.Time) {
			successTS = ts
		},
	}
	if err := svc.RunCycle(context.Background()); err != nil {
		t.Fatalf("RunCycle() error = %v", err)
	}
	if repo.createCalls != 1 {
		t.Fatalf("createCalls = %d, want 1", repo.createCalls)
	}
	if metrics.cycles != 1 || metrics.cycleStatus != "success" {
		t.Fatalf("metrics = %+v", metrics)
	}
	if metrics.newFindings["npm"] != 1 {
		t.Fatalf("new findings = %#v", metrics.newFindings)
	}
	if successTS.IsZero() {
		t.Fatal("expected OnSuccess timestamp")
	}
	if repo.setSuccessCalls != 1 {
		t.Fatal("expected last success update")
	}
}

func TestRunCycleDuplicateSkipped(t *testing.T) {
	repo := &memoryWatchRepo{
		lastSuccess: time.Now().UTC().Add(-time.Hour),
		catalog: []domain.WatchCatalogEntry{
			{ComponentVersionID: "cv-1", Name: "lodash", Ecosystem: "npm", Version: "4.17.20", ArtifactID: "sbom-1"},
		},
		existing: map[string]bool{"cv-1:CVE-2021-23337": true},
	}
	svc := &watch.Service{
		NVD: &stubNVD{records: []domain.FeedVulnerability{
			{CVEID: "CVE-2021-23337", PackageName: "lodash", Ecosystem: "npm", AffectedVersions: []string{"4.17.20"}},
		}},
		Repo: repo,
	}
	if err := svc.RunCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if repo.createCalls != 0 {
		t.Fatalf("createCalls = %d, want 0", repo.createCalls)
	}
}

func TestRunCycleNotifyFlushWithoutMatches(t *testing.T) {
	repo := &memoryWatchRepo{
		lastSuccess: time.Now().UTC(),
		catalog: []domain.WatchCatalogEntry{
			{ComponentVersionID: "cv-1", Name: "lodash", Ecosystem: "npm", Version: "4.17.20", ArtifactID: "sbom-1"},
		},
	}
	notifier := &recordingNotifier{}
	svc := &watch.Service{
		NVD: &stubNVD{records: []domain.FeedVulnerability{
			{CVEID: "CVE-1", PackageName: "other", Ecosystem: "npm", AffectedVersions: []string{"1"}},
		}},
		Repo:   repo,
		Notify: notifier,
	}
	if err := svc.RunCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if repo.createCalls != 0 {
		t.Fatalf("createCalls = %d, want 0", repo.createCalls)
	}
}

func TestRunCycleListStoredError(t *testing.T) {
	repo := &memoryWatchRepo{
		lastSuccess:   time.Now().UTC(),
		catalog:       []domain.WatchCatalogEntry{{Name: "lodash", Ecosystem: "npm"}},
		listStoredErr: errors.New("stored list failed"),
	}
	svc := &watch.Service{
		NVD:  &stubNVD{records: nil},
		Repo: repo,
	}
	if err := svc.RunCycle(context.Background()); err == nil {
		t.Fatal("expected stored list error")
	}
}

func TestRunCycleOSVSupplementQueryError(t *testing.T) {
	repo := &memoryWatchRepo{
		lastSuccess: time.Now().UTC(),
		catalog:     []domain.WatchCatalogEntry{{Name: "lodash", Ecosystem: "npm"}},
	}
	svc := &watch.Service{
		NVD:  &stubNVD{records: nil},
		OSV:  &stubOSV{err: errors.New("osv supplement failed")},
		Repo: repo,
	}
	if err := svc.RunCycle(context.Background()); err == nil {
		t.Fatal("expected osv supplement query error")
	}
}

func TestRunCycleOSVSupplementUpsertError(t *testing.T) {
	repo := &memoryWatchRepo{
		lastSuccess: time.Now().UTC(),
		catalog: []domain.WatchCatalogEntry{
			{ComponentVersionID: "cv-1", Name: "lodash", Ecosystem: "npm", Version: "4.17.20", ArtifactID: "sbom-1"},
		},
		upsertErr: errors.New("osv upsert failed"),
	}
	svc := &watch.Service{
		NVD: &stubNVD{records: nil},
		OSV: &stubOSV{records: []domain.FeedVulnerability{
			{CVEID: "CVE-1", PackageName: "lodash", Ecosystem: "npm", AffectedVersions: []string{"4.17.20"}},
		}},
		Repo: repo,
	}
	if err := svc.RunCycle(context.Background()); err == nil {
		t.Fatal("expected osv supplement upsert error")
	}
}

func TestRunCycleStoredCatalogMatch(t *testing.T) {
	repo := &memoryWatchRepo{
		lastSuccess: time.Now().UTC().Add(-time.Hour),
		catalog: []domain.WatchCatalogEntry{
			{ComponentVersionID: "cv-1", Name: "lodash", Ecosystem: "npm", Version: "4.17.20", ArtifactID: "sbom-1"},
		},
		storedRecords: []domain.VulnerabilityRecord{
			{ID: "vuln-1", CVEID: "CVE-2021-23337", Ecosystem: "npm", PackageName: "lodash", Severity: "high", AffectedVersions: []string{"< 4.17.21"}},
		},
	}
	svc := &watch.Service{
		NVD:  &stubNVD{records: nil},
		Repo: repo,
	}
	if err := svc.RunCycle(context.Background()); err != nil {
		t.Fatalf("RunCycle() error = %v", err)
	}
	if repo.createCalls != 1 {
		t.Fatalf("createCalls = %d, want 1", repo.createCalls)
	}
}

func TestRunCycleOSVFallback(t *testing.T) {
	repo := &memoryWatchRepo{
		lastSuccess: time.Now().UTC().Add(-time.Hour),
		catalog: []domain.WatchCatalogEntry{
			{ComponentVersionID: "cv-1", Name: "lodash", Ecosystem: "npm", Version: "4.17.20", ArtifactID: "sbom-1"},
		},
	}
	osv := &stubOSV{records: []domain.FeedVulnerability{
		{CVEID: "CVE-2021-23337", PackageName: "lodash", Ecosystem: "npm", AffectedVersions: []string{"4.17.20"}},
	}}
	svc := &watch.Service{
		NVD:  &stubNVD{err: errors.New("nvd down")},
		OSV:  osv,
		Repo: repo,
	}
	if err := svc.RunCycle(context.Background()); err != nil {
		t.Fatalf("RunCycle() error = %v", err)
	}
	if !osv.called {
		t.Fatal("expected OSV fallback")
	}
	if repo.createCalls != 1 {
		t.Fatalf("createCalls = %d, want 1", repo.createCalls)
	}
}

func TestRunCycleFailureDoesNotUpdateTimestamp(t *testing.T) {
	repo := &memoryWatchRepo{
		lastSuccess: time.Now().UTC().Add(-time.Hour),
		getErr:      errors.New("db down"),
	}
	svc := &watch.Service{
		NVD:     &stubNVD{records: nil},
		Repo:    repo,
		Metrics: &memoryMetrics{},
	}
	err := svc.RunCycle(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if repo.setSuccessCalls != 0 {
		t.Fatal("timestamp must not update on failure")
	}
}

func TestRunCycleBothFeedsFail(t *testing.T) {
	repo := &memoryWatchRepo{
		lastSuccess: time.Now().UTC().Add(-time.Hour),
		catalog:     []domain.WatchCatalogEntry{{Name: "lodash", Ecosystem: "npm"}},
	}
	svc := &watch.Service{
		NVD:  &stubNVD{err: errors.New("nvd down")},
		OSV:  &stubOSV{err: errors.New("osv down")},
		Repo: repo,
	}
	if err := svc.RunCycle(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}

func TestRunCycleNoClients(t *testing.T) {
	repo := &memoryWatchRepo{lastSuccess: time.Now().UTC()}
	svc := &watch.Service{Repo: repo}
	if err := svc.RunCycle(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}

func TestRunCycleUpsertFailure(t *testing.T) {
	repo := &memoryWatchRepo{
		lastSuccess: time.Now().UTC(),
		upsertErr:   errors.New("upsert failed"),
	}
	svc := &watch.Service{
		NVD:  &stubNVD{records: []domain.FeedVulnerability{{CVEID: "CVE-1"}}},
		Repo: repo,
	}
	if err := svc.RunCycle(context.Background()); err == nil {
		t.Fatal("expected upsert error")
	}
}

func TestRunCycleCreateNotCreated(t *testing.T) {
	repo := &memoryWatchRepo{
		lastSuccess: time.Now().UTC(),
		catalog: []domain.WatchCatalogEntry{
			{ComponentVersionID: "cv-1", Name: "lodash", Ecosystem: "npm", Version: "4.17.20", ArtifactID: "sbom-1"},
		},
	}
	repo.createHook = func() domain.CreateWatchFindingResult {
		return domain.CreateWatchFindingResult{Created: false}
	}
	svc := &watch.Service{
		NVD: &stubNVD{records: []domain.FeedVulnerability{
			{CVEID: "CVE-1", PackageName: "lodash", Ecosystem: "npm", AffectedVersions: []string{"4.17.20"}},
		}},
		Repo:    repo,
		Metrics: &memoryMetrics{},
	}
	if err := svc.RunCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRunCycleOSVOnly(t *testing.T) {
	repo := &memoryWatchRepo{
		lastSuccess: time.Now().UTC(),
		catalog: []domain.WatchCatalogEntry{
			{ComponentVersionID: "cv-1", Name: "lodash", Ecosystem: "npm", Version: "4.17.20", ArtifactID: "sbom-1"},
		},
	}
	svc := &watch.Service{
		OSV: &stubOSV{records: []domain.FeedVulnerability{
			{CVEID: "CVE-1", PackageName: "lodash", Ecosystem: "npm", AffectedVersions: []string{"4.17.20"}},
		}},
		Repo: repo,
	}
	if err := svc.RunCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRunCycleRepoErrors(t *testing.T) {
	base := &watch.Service{
		NVD: &stubNVD{records: []domain.FeedVulnerability{{CVEID: "CVE-1", PackageName: "lodash", Ecosystem: "npm", AffectedVersions: []string{"1"}}}},
	}
	ctx := context.Background()

	repo := &memoryWatchRepo{lastSuccess: time.Now().UTC(), listErr: errors.New("list")}
	svc := *base
	svc.Repo = repo
	if err := svc.RunCycle(ctx); err == nil {
		t.Fatal("expected list error")
	}

	repo = &memoryWatchRepo{
		lastSuccess: time.Now().UTC(),
		catalog:     []domain.WatchCatalogEntry{{ComponentVersionID: "cv-1", Name: "lodash", Ecosystem: "npm", Version: "1", ArtifactID: "sbom-1"}},
		hasErr:      errors.New("has"),
	}
	svc.Repo = repo
	if err := svc.RunCycle(ctx); err == nil {
		t.Fatal("expected has error")
	}

	repo = &memoryWatchRepo{
		lastSuccess: time.Now().UTC(),
		catalog:     []domain.WatchCatalogEntry{{ComponentVersionID: "cv-1", Name: "lodash", Ecosystem: "npm", Version: "1", ArtifactID: "sbom-1"}},
		createErr:   errors.New("create"),
	}
	svc.Repo = repo
	if err := svc.RunCycle(ctx); err == nil {
		t.Fatal("expected create error")
	}
}

func TestRunCycleMetricsNil(t *testing.T) {
	repo := &memoryWatchRepo{lastSuccess: time.Now().UTC()}
	svc := &watch.Service{NVD: &stubNVD{}, Repo: repo}
	if err := svc.RunCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRunCycleSetSuccessError(t *testing.T) {
	repo := &memoryWatchRepo{
		lastSuccess:   time.Now().UTC(),
		setSuccessErr: errors.New("set failed"),
	}
	svc := &watch.Service{NVD: &stubNVD{}, Repo: repo}
	if err := svc.RunCycle(context.Background()); err == nil {
		t.Fatal("expected set success error")
	}
}

func TestRunCycleOSVCatalogListError(t *testing.T) {
	repo := &memoryWatchRepo{
		lastSuccess:   time.Now().UTC(),
		listErrOnCall: 2,
		listErr:       errors.New("list failed"),
	}
	svc := &watch.Service{
		NVD:  &stubNVD{err: errors.New("nvd down")},
		OSV:  &stubOSV{},
		Repo: repo,
	}
	if err := svc.RunCycle(context.Background()); err == nil {
		t.Fatal("expected catalog list error during osv fallback")
	}
}

func TestRunCycleNVDFailsWithoutOSV(t *testing.T) {
	repo := &memoryWatchRepo{lastSuccess: time.Now().UTC()}
	svc := &watch.Service{
		NVD:  &stubNVD{err: errors.New("nvd down")},
		Repo: repo,
	}
	if err := svc.RunCycle(context.Background()); err == nil {
		t.Fatal("expected nvd error")
	}
}

func TestRunCycleOSVFallbackSkipsEmptyPackages(t *testing.T) {
	repo := &memoryWatchRepo{
		lastSuccess: time.Now().UTC(),
		catalog:     []domain.WatchCatalogEntry{{Name: "", Ecosystem: "npm"}},
	}
	osv := &stubOSV{}
	svc := &watch.Service{
		NVD:  &stubNVD{err: errors.New("nvd down")},
		OSV:  osv,
		Repo: repo,
	}
	if err := svc.RunCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if osv.called {
		t.Fatal("expected empty package batch to skip osv query")
	}
}

func TestRunCycleOSVQueryError(t *testing.T) {
	repo := &memoryWatchRepo{
		lastSuccess: time.Now().UTC(),
		catalog:     []domain.WatchCatalogEntry{{Name: "lodash", Ecosystem: "npm"}},
	}
	svc := &watch.Service{
		OSV:  &stubOSV{err: errors.New("osv query failed")},
		Repo: repo,
	}
	if err := svc.RunCycle(context.Background()); err == nil {
		t.Fatal("expected osv query error")
	}
}

func TestRunCycleMatchedUpsertFailure(t *testing.T) {
	repo := &memoryWatchRepo{
		lastSuccess: time.Now().UTC(),
		catalog: []domain.WatchCatalogEntry{
			{ComponentVersionID: "cv-1", Name: "lodash", Ecosystem: "npm", Version: "1", ArtifactID: "sbom-1"},
		},
	}
	upserts := 0
	repo.upsertHook = func() error {
		upserts++
		if upserts > 1 {
			return errors.New("matched upsert failed")
		}
		return nil
	}
	svc := &watch.Service{
		NVD: &stubNVD{records: []domain.FeedVulnerability{
			{CVEID: "CVE-1", PackageName: "lodash", Ecosystem: "npm", AffectedVersions: []string{"1"}},
		}},
		Repo: repo,
	}
	if err := svc.RunCycle(context.Background()); err == nil {
		t.Fatal("expected matched upsert error")
	}
}

type memoryWatchRepo struct {
	lastSuccess     time.Time
	catalog         []domain.WatchCatalogEntry
	storedRecords   []domain.VulnerabilityRecord
	existing        map[string]bool
	createCalls     int
	setSuccessCalls int
	setSuccessErr   error
	getErr          error
	listCalls       int
	listErrOnCall   int
	listErr         error
	listStoredErr   error
	upsertErr       error
	createErr       error
	hasErr          error
	createHook      func() domain.CreateWatchFindingResult
	upsertHook      func() error
}

func (m *memoryWatchRepo) ListWatchCatalog(context.Context) ([]domain.WatchCatalogEntry, error) {
	m.listCalls++
	if m.listErr != nil && (m.listErrOnCall == 0 || m.listCalls >= m.listErrOnCall) {
		return nil, m.listErr
	}
	return m.catalog, nil
}

func (m *memoryWatchRepo) ListVulnerabilityRecords(context.Context) ([]domain.VulnerabilityRecord, error) {
	if m.listStoredErr != nil {
		return nil, m.listStoredErr
	}
	return m.storedRecords, nil
}

func (m *memoryWatchRepo) GetLastSuccessTimestamp(context.Context) (time.Time, error) {
	if m.getErr != nil {
		return time.Time{}, m.getErr
	}
	return m.lastSuccess, nil
}

func (m *memoryWatchRepo) SetLastSuccessTimestamp(context.Context, time.Time) error {
	m.setSuccessCalls++
	return m.setSuccessErr
}

func (m *memoryWatchRepo) UpsertVulnerability(_ context.Context, record domain.VulnerabilityRecord) (string, error) {
	if m.upsertHook != nil {
		if err := m.upsertHook(); err != nil {
			return "", err
		}
	}
	if m.upsertErr != nil {
		return "", m.upsertErr
	}
	return "vuln-" + record.CVEID, nil
}

func (m *memoryWatchRepo) HasFinding(_ context.Context, componentVersionID, cveID string) (bool, error) {
	if m.hasErr != nil {
		return false, m.hasErr
	}
	if m.existing == nil {
		return false, nil
	}
	return m.existing[componentVersionID+":"+cveID], nil
}

func (m *memoryWatchRepo) CreateWatchFinding(_ context.Context, _ domain.CreateWatchFindingInput) (domain.CreateWatchFindingResult, error) {
	if m.createErr != nil {
		return domain.CreateWatchFindingResult{}, m.createErr
	}
	m.createCalls++
	if m.createHook != nil {
		return m.createHook(), nil
	}
	return domain.CreateWatchFindingResult{ComponentVulnerabilityID: "finding-1", Created: true}, nil
}

type stubNVD struct {
	records []domain.FeedVulnerability
	err     error
}

func (s *stubNVD) FetchModifiedSince(context.Context, time.Time) ([]domain.FeedVulnerability, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.records, nil
}

type stubOSV struct {
	records []domain.FeedVulnerability
	err     error
	called  bool
}

func (s *stubOSV) QueryByEcosystem(_ context.Context, _ string, _ []domain.OSVPackageQuery) ([]domain.FeedVulnerability, error) {
	s.called = true
	if s.err != nil {
		return nil, s.err
	}
	return s.records, nil
}

type memoryMetrics struct {
	cycles      int
	cycleStatus string
	newFindings map[string]int
}

func (m *memoryMetrics) RecordCycle(status string, _ time.Duration) {
	m.cycles++
	m.cycleStatus = status
	if m.newFindings == nil {
		m.newFindings = map[string]int{}
	}
}

func (m *memoryMetrics) RecordNewFindings(ecosystem string, count int) {
	if m.newFindings == nil {
		m.newFindings = map[string]int{}
	}
	m.newFindings[ecosystem] += count
}

type recordingNotifier struct {
	events []domain.NotificationEvent
}

func (r *recordingNotifier) Dispatch(_ context.Context, event domain.NotificationEvent) error {
	r.events = append(r.events, event)
	return nil
}

func (recordingNotifier) FlushDigest(context.Context, string) error { return nil }
