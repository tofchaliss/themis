package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/evidence/app"
	"github.com/themis-project/themis/internal/evidence/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

type fakeTrust struct {
	out app.TrustOutcome
	err error
}

func (f fakeTrust) Admit(app.TrustInput) (app.TrustOutcome, error) { return f.out, f.err }

type fakeParser struct {
	inv    domain.Inventory
	err    error
	called bool
}

func (f *fakeParser) Parse(context.Context, string, string, []byte) (domain.Inventory, []string, error) {
	f.called = true
	return f.inv, nil, f.err
}

type fakeSubject struct {
	ok  bool
	err error
}

func (f fakeSubject) ReleaseExists(context.Context, string) (bool, error) { return f.ok, f.err }

type fakeRepo struct {
	saveID      domain.EvidenceID
	saveCreated bool
	saveErr     error
	saved       domain.Evidence
	getEv       domain.Evidence
	getErr      error
	inv         domain.Inventory
	invErr      error
	list        []app.EvidenceSummary
	listErr     error
}

func (f *fakeRepo) Save(_ context.Context, e domain.Evidence, _ []byte, _ domain.EvidenceRegistered) (domain.EvidenceID, bool, error) {
	f.saved = e
	return f.saveID, f.saveCreated, f.saveErr
}
func (f *fakeRepo) GetByID(context.Context, domain.EvidenceID) (domain.Evidence, error) {
	return f.getEv, f.getErr
}
func (f *fakeRepo) GetInventory(context.Context, domain.EvidenceID) (domain.Inventory, error) {
	return f.inv, f.invErr
}
func (f *fakeRepo) ListByRelease(context.Context, string) ([]app.EvidenceSummary, error) {
	return f.list, f.listErr
}

type fakeIDs struct{ id domain.EvidenceID }

func (f fakeIDs) NewID() domain.EvidenceID { return f.id }

type fakeClock struct{}

func (fakeClock) Now() time.Time { return time.Unix(1_700_000_000, 0) }

func acceptedTrust() app.TrustOutcome {
	return app.TrustOutcome{
		Fingerprint: value.NewContentFingerprint([]byte("raw")),
		Status:      domain.TrustAccepted,
		Provenance:  domain.Provenance{Source: "trivy"},
	}
}

func inventory(t *testing.T) domain.Inventory {
	t.Helper()
	p, err := value.NewPURL("pkg:deb/debian/openssl@3.0.11")
	if err != nil {
		t.Fatal(err)
	}
	return domain.NewInventory([]domain.Component{{PURL: p, Name: "openssl"}}, nil)
}

func newService(trust app.TrustGate, parser app.Parser, subject app.SubjectRefValidator, repo app.Repository) *app.EvidenceService {
	return app.NewEvidenceService(trust, parser, subject, repo, fakeIDs{id: "ev-1"}, fakeClock{})
}

func TestRegister_SBOM_Success(t *testing.T) {
	parser := &fakeParser{inv: inventory(t)}
	repo := &fakeRepo{saveID: "ev-1", saveCreated: true}
	svc := newService(fakeTrust{out: acceptedTrust()}, parser, fakeSubject{ok: true}, repo)

	res, err := svc.Register(context.Background(), app.RegisterCommand{
		Raw: []byte("raw"), Kind: domain.KindSBOM, Format: "cyclonedx", SubjectReleaseID: "rel-1",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if res.ID != "ev-1" || !res.Created {
		t.Errorf("result = %+v", res)
	}
	if !parser.called {
		t.Error("parser should be called for SBOM")
	}
	if repo.saved.Kind() != domain.KindSBOM || repo.saved.Subject().ReleaseID != "rel-1" {
		t.Errorf("saved evidence = %+v", repo.saved)
	}
}

func TestRegister_NonSBOM_SkipsParser(t *testing.T) {
	parser := &fakeParser{}
	repo := &fakeRepo{saveID: "ev-1", saveCreated: true}
	svc := newService(fakeTrust{out: acceptedTrust()}, parser, fakeSubject{ok: true}, repo)

	if _, err := svc.Register(context.Background(), app.RegisterCommand{Raw: []byte("raw"), Kind: domain.KindVEX, SubjectReleaseID: "rel-1"}); err != nil {
		t.Fatalf("register vex: %v", err)
	}
	if parser.called {
		t.Error("parser must not be called for non-SBOM kinds")
	}
	if !repo.saved.Inventory().IsEmpty() {
		t.Error("non-SBOM evidence should carry an empty inventory")
	}
}

func TestRegister_Failures(t *testing.T) {
	boom := errors.New("boom")
	ctx := context.Background()

	t.Run("unknown subject", func(t *testing.T) {
		svc := newService(fakeTrust{out: acceptedTrust()}, &fakeParser{}, fakeSubject{ok: false}, &fakeRepo{})
		if _, err := svc.Register(ctx, app.RegisterCommand{Kind: domain.KindSBOM, SubjectReleaseID: "nope"}); !errors.Is(err, app.ErrUnknownSubject) {
			t.Errorf("err = %v, want ErrUnknownSubject", err)
		}
	})
	t.Run("subject error", func(t *testing.T) {
		svc := newService(fakeTrust{out: acceptedTrust()}, &fakeParser{}, fakeSubject{err: boom}, &fakeRepo{})
		if _, err := svc.Register(ctx, app.RegisterCommand{Kind: domain.KindSBOM, SubjectReleaseID: "rel-1"}); !errors.Is(err, boom) {
			t.Errorf("err = %v, want boom", err)
		}
	})
	t.Run("trust rejected", func(t *testing.T) {
		out := app.TrustOutcome{Fingerprint: value.NewContentFingerprint([]byte("x")), Status: domain.TrustRejected, Reason: "bad"}
		svc := newService(fakeTrust{out: out}, &fakeParser{}, fakeSubject{ok: true}, &fakeRepo{})
		if _, err := svc.Register(ctx, app.RegisterCommand{Kind: domain.KindSBOM, SubjectReleaseID: "rel-1"}); !errors.Is(err, app.ErrRejected) {
			t.Errorf("err = %v, want ErrRejected", err)
		}
	})
	t.Run("trust error", func(t *testing.T) {
		svc := newService(fakeTrust{err: boom}, &fakeParser{}, fakeSubject{ok: true}, &fakeRepo{})
		if _, err := svc.Register(ctx, app.RegisterCommand{Kind: domain.KindSBOM, SubjectReleaseID: "rel-1"}); !errors.Is(err, boom) {
			t.Errorf("err = %v, want boom", err)
		}
	})
	t.Run("parse error", func(t *testing.T) {
		svc := newService(fakeTrust{out: acceptedTrust()}, &fakeParser{err: boom}, fakeSubject{ok: true}, &fakeRepo{})
		if _, err := svc.Register(ctx, app.RegisterCommand{Kind: domain.KindSBOM, SubjectReleaseID: "rel-1"}); !errors.Is(err, boom) {
			t.Errorf("err = %v, want boom", err)
		}
	})
	t.Run("build error (zero fingerprint)", func(t *testing.T) {
		out := app.TrustOutcome{Status: domain.TrustAccepted} // zero fingerprint → NewEvidence fails
		svc := newService(fakeTrust{out: out}, &fakeParser{inv: inventory(t)}, fakeSubject{ok: true}, &fakeRepo{})
		if _, err := svc.Register(ctx, app.RegisterCommand{Kind: domain.KindSBOM, SubjectReleaseID: "rel-1"}); err == nil {
			t.Error("want build error on zero fingerprint")
		}
	})
	t.Run("save error", func(t *testing.T) {
		svc := newService(fakeTrust{out: acceptedTrust()}, &fakeParser{inv: inventory(t)}, fakeSubject{ok: true}, &fakeRepo{saveErr: boom})
		if _, err := svc.Register(ctx, app.RegisterCommand{Kind: domain.KindSBOM, SubjectReleaseID: "rel-1"}); !errors.Is(err, boom) {
			t.Errorf("err = %v, want boom", err)
		}
	})
}

func TestReads(t *testing.T) {
	ctx := context.Background()
	repo := &fakeRepo{
		getEv:  mustEvidence(t),
		inv:    inventory(t),
		list:   []app.EvidenceSummary{{ID: "ev-1", Kind: domain.KindSBOM}},
		getErr: nil,
	}
	svc := newService(fakeTrust{}, &fakeParser{}, fakeSubject{}, repo)

	if _, err := svc.GetEvidence(ctx, "ev-1"); err != nil {
		t.Errorf("GetEvidence: %v", err)
	}
	if _, err := svc.GetInventory(ctx, "ev-1"); err != nil {
		t.Errorf("GetInventory: %v", err)
	}
	list, err := svc.ListByRelease(ctx, "rel-1")
	if err != nil || len(list) != 1 {
		t.Errorf("ListByRelease: %v %+v", err, list)
	}
}

func mustEvidence(t *testing.T) domain.Evidence {
	t.Helper()
	e, err := domain.NewEvidence("ev-1", domain.KindSBOM, value.NewContentFingerprint([]byte("x")),
		domain.SubjectRef{ReleaseID: "rel-1"}, domain.Provenance{}, domain.TrustAccepted, inventory(t), time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	return e
}
