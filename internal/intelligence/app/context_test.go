package app

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

type fakeFindingReader struct {
	view domain.FindingView
	err  error
}

func (f fakeFindingReader) GetFinding(_ context.Context, _ string) (domain.FindingView, error) {
	return f.view, f.err
}

type fakeFaultlineReader struct {
	view domain.FaultlineView
	err  error
}

func (f fakeFaultlineReader) GetFaultline(_ context.Context, _ string) (domain.FaultlineView, error) {
	return f.view, f.err
}

var bothNeeds = []domain.ContextNeed{domain.NeedFinding, domain.NeedFaultline}

func TestAssembleContextHappy(t *testing.T) {
	fr := fakeFindingReader{view: domain.FindingView{ID: "F1", FaultlineID: "FL1"}}
	flr := fakeFaultlineReader{view: domain.FaultlineView{ID: "FL1", CVE: "CVE-1"}}
	ac, err := AssembleContext(context.Background(), fr, flr, bothNeeds, "F1")
	if err != nil {
		t.Fatalf("AssembleContext err: %v", err)
	}
	if ac.Finding.ID != "F1" || ac.Faultline.ID != "FL1" {
		t.Errorf("unexpected context %+v", ac)
	}
}

func TestAssembleContextFindingNotFound(t *testing.T) {
	fr := fakeFindingReader{view: domain.FindingView{}} // empty ID = not found
	_, err := AssembleContext(context.Background(), fr, fakeFaultlineReader{}, bothNeeds, "missing")
	if !errors.Is(err, ErrIncompleteGrounding) {
		t.Errorf("want ErrIncompleteGrounding, got %v", err)
	}
}

func TestAssembleContextFindingError(t *testing.T) {
	fr := fakeFindingReader{err: errors.New("boom")}
	if _, err := AssembleContext(context.Background(), fr, fakeFaultlineReader{}, bothNeeds, "F1"); err == nil {
		t.Error("expected finding reader error")
	}
}

func TestAssembleContextMissingFaultlineID(t *testing.T) {
	fr := fakeFindingReader{view: domain.FindingView{ID: "F1", FaultlineID: ""}}
	_, err := AssembleContext(context.Background(), fr, fakeFaultlineReader{}, bothNeeds, "F1")
	if !errors.Is(err, ErrIncompleteGrounding) {
		t.Errorf("want ErrIncompleteGrounding, got %v", err)
	}
}

func TestAssembleContextFaultlineError(t *testing.T) {
	fr := fakeFindingReader{view: domain.FindingView{ID: "F1", FaultlineID: "FL1"}}
	flr := fakeFaultlineReader{err: errors.New("boom")}
	if _, err := AssembleContext(context.Background(), fr, flr, bothNeeds, "F1"); err == nil {
		t.Error("expected faultline reader error")
	}
}

func TestAssembleContextFaultlineNotFound(t *testing.T) {
	fr := fakeFindingReader{view: domain.FindingView{ID: "F1", FaultlineID: "FL1"}}
	flr := fakeFaultlineReader{view: domain.FaultlineView{}} // empty ID = not found
	_, err := AssembleContext(context.Background(), fr, flr, bothNeeds, "F1")
	if !errors.Is(err, ErrIncompleteGrounding) {
		t.Errorf("want ErrIncompleteGrounding, got %v", err)
	}
}

func TestAssembleContextFindingOnly(t *testing.T) {
	fr := fakeFindingReader{view: domain.FindingView{ID: "F1", FaultlineID: "FL1"}}
	ac, err := AssembleContext(context.Background(), fr, fakeFaultlineReader{}, []domain.ContextNeed{domain.NeedFinding}, "F1")
	if err != nil {
		t.Fatalf("AssembleContext err: %v", err)
	}
	if ac.Faultline.ID != "" {
		t.Error("faultline should not be assembled when not needed")
	}
}
