package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// noticeStore is the in-memory FixNoticeStore: notices keyed like the table, announcements kept
// with their notes so a test can read what went out.
type noticeStore struct {
	recorded   []app.FixNotice
	pending    []app.FixNotice
	announced  map[string][]app.FixNotice
	notes      []app.OutboxNote
	recordErr  error
	pendingErr error
	markErr    error
}

func (s *noticeStore) RecordFixNotices(_ context.Context, n []app.FixNotice) error {
	if s.recordErr != nil {
		return s.recordErr
	}
	s.recorded = append(s.recorded, n...)
	return nil
}

func (s *noticeStore) PendingFixNotices(context.Context, int) ([]app.FixNotice, error) {
	return s.pending, s.pendingErr
}

func (s *noticeStore) MarkFixNoticesAnnounced(_ context.Context, rel string, n []app.FixNotice, note app.OutboxNote) error {
	if s.markErr != nil {
		return s.markErr
	}
	if s.announced == nil {
		s.announced = map[string][]app.FixNotice{}
	}
	s.announced[rel] = append(s.announced[rel], n...)
	s.notes = append(s.notes, note)
	return nil
}

// EDR-INCIDENT-01 D1, the recording half: one notice per NEW bound, carrying the occurrence's
// key and the advisories; a fact with no release, no package or no bound records nothing and
// is not an error; a Coordinator without the store ignores the fact.
func TestCoordinator_OnFixPublished(t *testing.T) {
	ctx := context.Background()
	st := &noticeStore{}
	c := app.NewCoordinator(writeSvc(newRepo())).WithFixNotices(st)
	at := fixedNow
	in := app.InboundFixPublished{
		FaultlineID: "fl-1", CVE: "CVE-2026-1", ReleaseID: "rel-1", PURL: "pkg:rpm/redhat/kernel@4.18.0-553.el8_10",
		Package: "kernel", Ecosystem: "rpm", Fixes: []string{"0:4.18.0-553.80.1.el8_10", " ", "0:4.18.0-553.72.1.el8_10"},
		Advisories: []string{"RHSA-2026:1"}, OccurredAt: at,
	}
	if err := c.OnFixPublished(ctx, in); err != nil {
		t.Fatal(err)
	}
	if len(st.recorded) != 2 {
		t.Fatalf("recorded = %+v, want one notice per non-blank bound", st.recorded)
	}
	n := st.recorded[0]
	if n.ReleaseID != "rel-1" || n.FaultlineID != "fl-1" || n.CVE != "CVE-2026-1" || n.PURL != in.PURL || n.Package != "kernel" ||
		n.Ecosystem != "rpm" || n.Fix != "0:4.18.0-553.80.1.el8_10" || len(n.Advisories) != 1 || !n.LearnedAt.Equal(at) {
		t.Errorf("notice = %+v", n)
	}
	for name, bad := range map[string]app.InboundFixPublished{
		"no release": {FaultlineID: "fl-1", Package: "kernel", Fixes: []string{"x"}},
		"no card":    {ReleaseID: "rel-1", Package: "kernel", Fixes: []string{"x"}},
		"no package": {ReleaseID: "rel-1", FaultlineID: "fl-1", Fixes: []string{"x"}},
		"no bound":   {ReleaseID: "rel-1", FaultlineID: "fl-1", Package: "kernel", Fixes: []string{""}},
	} {
		st.recorded = nil
		if err := c.OnFixPublished(ctx, bad); err != nil || len(st.recorded) != 0 {
			t.Errorf("%s: err=%v recorded=%d, want nothing and no error", name, err, len(st.recorded))
		}
	}
	st.recordErr = errors.New("db")
	if err := c.OnFixPublished(ctx, in); err == nil {
		t.Error("a store fault must surface so the event is retried")
	}
	if err := app.NewCoordinator(writeSvc(newRepo())).OnFixPublished(ctx, in); err != nil {
		t.Errorf("without a notice store the fact is ignored, got %v", err)
	}
}

// The announcing half: pending notices become ONE announcement per release, in the order the
// releases were listed; a release's notices merge per (Finding, package) into one item with
// every bound and advisory once; the marked notices are exactly the release's; the note is the
// fix_available event stamped at the sweep time.
func TestFixAvailableSweep_OneAnnouncementPerRelease(t *testing.T) {
	st := &noticeStore{pending: []app.FixNotice{
		{ReleaseID: "rel-1", FaultlineID: "fl-1", CVE: "CVE-2026-1", FindingID: "fnd-1", PURL: "p1", Package: "kernel", Ecosystem: "rpm", Fix: "0:4.18.0-553.72.1.el8_10", Advisories: []string{"RHSA-2026:1"}},
		{ReleaseID: "rel-2", FaultlineID: "fl-1", CVE: "CVE-2026-1", FindingID: "fnd-9", PURL: "p9", Package: "kernel", Ecosystem: "rpm", Fix: "0:4.18.0-553.72.1.el8_10"},
		{ReleaseID: "rel-1", FaultlineID: "fl-1", CVE: "CVE-2026-1", FindingID: "fnd-1", PURL: "p1", Package: "kernel", Ecosystem: "rpm", Fix: "0:4.18.0-553.80.1.el8_10", Advisories: []string{"RHSA-2026:1", "RHSA-2026:2", " "}}, // a blank advisory is dropped
		{ReleaseID: "rel-1", FaultlineID: "fl-1", CVE: "CVE-2026-1", FindingID: "fnd-1", PURL: "p1-devel", Package: "kernel", Ecosystem: "rpm", Fix: "0:4.18.0-553.80.1.el8_10"},                                                    // a second rpm of the same source package: same item
		{ReleaseID: "rel-1", FaultlineID: "fl-2", CVE: "CVE-2026-2", FindingID: "fnd-2", PURL: "p2", Package: "openssl", Ecosystem: "rpm", Fix: "1:1.1.1k-14.el8_6"},
	}}
	sweep := app.NewFixAvailableSweep(st, fixedClock{})
	n, err := sweep.Run(context.Background())
	if err != nil || n != 2 {
		t.Fatalf("run = %d/%v, want 2 releases announced", n, err)
	}
	if len(st.announced["rel-1"]) != 4 || len(st.announced["rel-2"]) != 1 || len(st.notes) != 2 {
		t.Fatalf("announced = %+v notes=%d", st.announced, len(st.notes))
	}
	note := st.notes[0]
	ev, ok := note.Event.(domain.FixAvailable)
	if note.EventType != app.EventFixAvailable || !ok || !note.OccurredAt.Equal(fixedNow) || !ev.OccurredAt.Equal(fixedNow) {
		t.Fatalf("note = %+v", note)
	}
	if ev.ReleaseID != "rel-1" || ev.CVECount != 2 || ev.PackageCount != 2 || len(ev.Items) != 2 {
		t.Fatalf("event = %+v, want rel-1 with 2 CVEs, 2 packages, 2 items", ev)
	}
	k := ev.Items[0]
	if k.FindingID != "fnd-1" || k.CVE != "CVE-2026-1" || k.Package != "kernel" || k.Ecosystem != "rpm" ||
		len(k.Fixes) != 2 || len(k.Advisories) != 2 || k.Advisories[0] != "RHSA-2026:1" || k.Advisories[1] != "RHSA-2026:2" {
		t.Errorf("kernel item = %+v, want both bounds and both advisories once", k)
	}
	if o := ev.Items[1]; o.Package != "openssl" || len(o.Fixes) != 1 || o.Advisories != nil {
		t.Errorf("openssl item = %+v", o)
	}
	if ev2 := st.notes[1].Event.(domain.FixAvailable); ev2.ReleaseID != "rel-2" || ev2.CVECount != 1 {
		t.Errorf("second event = %+v", ev2)
	}

	// Nothing pending: nothing announced, no error.
	st.pending = nil
	if n, err := sweep.Run(context.Background()); err != nil || n != 0 {
		t.Errorf("empty run = %d/%v", n, err)
	}
}

func TestFixAvailableSweep_Failures(t *testing.T) {
	ctx := context.Background()
	if _, err := app.NewFixAvailableSweep(&noticeStore{pendingErr: errors.New("db")}, fixedClock{}).Run(ctx); err == nil {
		t.Error("a listing fault must surface")
	}
	pending := []app.FixNotice{{ReleaseID: "rel-1", FaultlineID: "fl-1", CVE: "CVE-1", Package: "kernel", Fix: "x"}}
	if n, err := app.NewFixAvailableSweep(&noticeStore{pending: pending, markErr: errors.New("db")}, fixedClock{}).Run(ctx); err == nil || n != 0 {
		t.Errorf("a marking fault must surface with nothing counted, got %d/%v", n, err)
	}
	// A cancelled context stops the pass between releases.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := app.NewFixAvailableSweep(&noticeStore{pending: pending}, fixedClock{}).Run(cctx); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled run = %v, want context.Canceled", err)
	}
}

// RunEvery ticks until the context ends and reports each pass.
func TestFixAvailableSweep_RunEvery(t *testing.T) {
	st := &noticeStore{pending: []app.FixNotice{{ReleaseID: "rel-1", FaultlineID: "fl-1", CVE: "CVE-1", Package: "kernel", Fix: "x"}}}
	ctx, cancel := context.WithCancel(context.Background())
	reports := make(chan int, 8)
	go app.NewFixAvailableSweep(st, fixedClock{}).RunEvery(ctx, time.Millisecond, func(n int, err error) {
		if err != nil {
			t.Error(err)
		}
		reports <- n
	})
	select {
	case n := <-reports:
		if n != 1 {
			t.Errorf("first pass announced %d, want 1", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no pass ran")
	}
	cancel()
	// The nil reporter path.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel2()
	app.NewFixAvailableSweep(&noticeStore{}, fixedClock{}).RunEvery(ctx2, time.Millisecond, nil)
}
