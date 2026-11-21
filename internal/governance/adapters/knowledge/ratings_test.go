package knowledge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSourceRatings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/faultlines/fl-1/ratings" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"cve":"CVE-2026-1","observations":[
			{"id":"o1","document_ref":"nvd:CVE-2026-1","fingerprint":"fp1","updated_at":{"original":"x","instant":"2026-11-10T10:00:00+05:30","interpretation":"zone_stated"}},
			{"id":"o2","document_ref":"redhat:CVE-2026-1","revision":"7","updated_at":{"original":"??","interpretation":"unparseable"}}],
		"ratings":[
			{"id":"r1","observation_id":"o1","source":"nvd","feed":"nvd-api-2.0","assessor":"secalert@redhat.com","assessor_key":"redhat","publisher":"nvd","nvd_type":"Secondary","cvss_version":"3.1","vector":"CVSS:3.1/AV:N","inherited_context":"openssl","status":"active","validation":{"result":"invalid_vector","reason":"bad"},"identity":{"key":"redhat|3.1|v|"}},
			{"id":"r2","observation_id":"o2","source":"redhat","feed":"redhat-hydra","assessor":"RedHat","cvss_version":"3.1","vector":"v","asserted_context":"pkg","status":"withdrawn"}]}`))
	}))
	defer srv.Close()
	got, err := NewClient(srv.URL, srv.Client()).SourceRatings(context.Background(), "fl-1")
	if err != nil || len(got) != 2 {
		t.Fatalf("got %+v %v", got, err)
	}
	a, b := got[0], got[1]
	if a.Assessor != "redhat" || !a.Active || a.Validation != "invalid_vector" || a.ValidationReason != "bad" || a.IdentityKey == "" ||
		a.Revision != "fp1" || a.DocumentRef != "nvd:CVE-2026-1" || !a.SourceUpdatedAt.Equal(time.Date(2026, 11, 10, 4, 30, 0, 0, time.UTC)) || a.NVDType != "Secondary" {
		t.Errorf("a = %+v", a)
	}
	if b.Assessor != "redhat" || b.Active || b.Revision != "7" || !b.SourceUpdatedAt.IsZero() || b.AssertedContext != "pkg" {
		t.Errorf("b = %+v", b)
	}
}

func TestSourceRatingsErrors(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"status": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) },
		"body":   func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{`)) },
	} {
		srv := httptest.NewServer(h)
		if _, err := NewClient(srv.URL, srv.Client()).SourceRatings(context.Background(), "fl-1"); err == nil {
			t.Errorf("%s: no error", name)
		}
		srv.Close()
	}
	if _, err := NewClient("http://127.0.0.1:1", nil).SourceRatings(context.Background(), "fl-1"); err == nil {
		t.Error("transport error swallowed")
	}
	if _, err := NewClient("http://x\x7f", nil).SourceRatings(context.Background(), "fl-1"); err == nil {
		t.Error("bad url accepted")
	}
}
