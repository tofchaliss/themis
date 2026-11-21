package feed_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/adapters/feed"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// NVD (F10): every metric is kept as a publication, Primary and Secondary, each with its
// assessor; the single headline is unchanged.
func TestNVDClient_ObservationKeepsEveryMetric(t *testing.T) {
	srv := nvdServer(t, cve("CVE-2024-3000", `{
		"cvssMetricV31":[
			{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"3.1","baseScore":9.8,"baseSeverity":"CRITICAL","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
			{"source":"secalert@redhat.com","type":"Secondary","cvssData":{"baseScore":7.5,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}}],
		"cvssMetricV2":[{"type":"Primary","baseSeverity":"HIGH","cvssData":{"version":"2.0","baseScore":7.5,"vectorString":"AV:N/AC:L/Au:N/C:P/I:P/A:P"}}],
		"cvssMetricV40":[{"source":"x","type":"Secondary","cvssData":{"vectorString":""}}]}`))
	got, _, err := feed.NewNVDClient(srv.URL, "", srv.Client()).ChangedSince(context.Background(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	pf := onlyProposal(t, got)
	if vf, _ := pf.Proposal.VulnFacts(); vf.CVSS.Score() != 9.8 {
		t.Errorf("headline moved: %.1f", vf.CVSS.Score())
	}
	obs, ok := pf.Proposal.Observation()
	if !ok || obs.Source != "nvd" || obs.DocumentRef != "nvd:CVE-2024-3000" || !obs.Complete ||
		obs.UpdatedAt.Interpretation != domain.TimeZoneAssumedUTC {
		t.Fatalf("observation: %+v", obs)
	}
	if len(obs.Ratings) != 3 {
		t.Fatalf("ratings = %d, want 3 (the empty v4.0 vector is skipped): %+v", len(obs.Ratings), obs.Ratings)
	}
	sec, v2 := obs.Ratings[1], obs.Ratings[2]
	if sec.Assessor != "secalert@redhat.com" || sec.NVDType != "Secondary" || sec.Version != "3.1" || sec.StatedScore != 7.5 {
		t.Errorf("secondary: %+v", sec)
	}
	if v2.Assessor != "nvd" || v2.Version != "2.0" || v2.SeverityWord != "HIGH" {
		t.Errorf("v2: %+v", v2)
	}
}

// Red Hat (F11): the document rides the first Proposal even with no cvss3, so its withdrawal
// can be recorded.
func TestRedHatClient_ObservationWithAndWithoutScore(t *testing.T) {
	scored := `{"name":"CVE-2024-1","threat_severity":"Important","public_date":"2024-01-15T00:00:00Z",
		"cvss3":{"cvss3_base_score":"7.5","cvss3_scoring_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
		"package_state":[{"product_name":"RHEL 9","fix_state":"Not affected","package_name":"openssl","cpe":"cpe:/o:redhat:enterprise_linux:9"}],
		"affected_release":[{"product_name":"RHEL 8","package":"curl-0:7.61.1-1.el8","cpe":"cpe:/o:redhat:enterprise_linux:8","advisory":"RHSA-2024:1"}]}`
	srv := rhServer(t, http.StatusOK, scored)
	got, err := feed.NewRedHatClient(srv.URL, srv.Client()).FetchCVE(context.Background(), "CVE-2024-1")
	if err != nil || len(got) == 0 {
		t.Fatalf("fetch: %v %d", err, len(got))
	}
	obs, ok := got[0].Proposal.Observation()
	if !ok || len(obs.Ratings) != 1 || len(obs.Applicability) != 2 || obs.Fetch.HTTPStatus != http.StatusOK {
		t.Fatalf("observation: %+v", obs)
	}
	if r := obs.Ratings[0]; r.Assessor != "redhat" || r.Version != "3.1" || r.StatedScore != 7.5 || !r.HasStatedScore || r.SeverityWord != "Important" {
		t.Errorf("rating: %+v", r)
	}
	for _, p := range got[1:] {
		if _, attached := p.Proposal.Observation(); attached {
			t.Error("the document rides one Proposal only")
		}
	}

	unscored := `{"name":"CVE-2024-1","public_date":"2024-01-15T00:00:00Z",
		"cvss3":{"cvss3_base_score":"n/a","cvss3_scoring_vector":"AV:N/AC:L"},
		"package_state":[{"product_name":"RHEL 9","fix_state":"Not affected","package_name":"openssl"}]}`
	srv = rhServer(t, http.StatusOK, unscored)
	got, _ = feed.NewRedHatClient(srv.URL, srv.Client()).FetchCVE(context.Background(), "CVE-2024-1")
	obs, ok = got[0].Proposal.Observation()
	if !ok || len(obs.Ratings) != 1 || obs.Ratings[0].HasStatedScore || obs.Ratings[0].Version != "3.x" {
		t.Errorf("unparseable score / unknown version: %+v", obs)
	}
	noScore := `{"name":"CVE-2024-1","public_date":"2024-01-15T00:00:00Z",
		"package_state":[{"product_name":"RHEL 9","fix_state":"Not affected","package_name":"openssl"}]}`
	srv = rhServer(t, http.StatusOK, noScore)
	got, _ = feed.NewRedHatClient(srv.URL, srv.Client()).FetchCVE(context.Background(), "CVE-2024-1")
	if obs, ok = got[0].Proposal.Observation(); !ok || len(obs.Ratings) != 0 || !obs.Complete {
		t.Errorf("a complete document without cvss3: %+v", obs)
	}
}

const cveOrgRecord = `{
 "cveMetadata":{"cveId":"CVE-2024-5000","state":"PUBLISHED","dateUpdated":"2024-05-01T10:00:00.000Z"},
 "containers":{
  "cna":{"providerMetadata":{"orgId":"o-1","shortName":"redhat"},
   "affected":[{"vendor":"Red Hat","product":"Enterprise Linux","packageName":"openssl"},{"vendor":"n/a","product":"n/a"}],
   "metrics":[{"cvssV3_1":{"version":"3.1","baseScore":7.5,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}},
              {"other":{"type":"ssvc"}}]},
  "adp":[{"providerMetadata":{"orgId":"134c704f-9b21-4f2e-91b3-4a467353bcc0"},
   "metrics":[{"cvssV3_1":{"baseScore":9.8,"baseSeverity":"CRITICAL","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
               "cvssV4_0":{"version":"4.0","baseScore":9.3,"vectorString":"CVSS:4.0/AV:N"}}]}]}}`

func TestCVEOrgObservation(t *testing.T) {
	obs, ok, err := feed.CVEOrgObservation([]byte(cveOrgRecord))
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	if obs.Source != "cveorg" || obs.DocumentRef != "cveorg:CVE-2024-5000" || obs.UpdatedAt.Interpretation != domain.TimeZoneStated ||
		len(obs.Applicability) != 1 || obs.Applicability[0] != "Red Hat:Enterprise Linux:openssl" {
		t.Fatalf("observation: %+v", obs)
	}
	if len(obs.Ratings) != 3 {
		t.Fatalf("ratings: %+v", obs.Ratings)
	}
	if r := obs.Ratings[0]; r.Assessor != "redhat" || r.Publisher != "cve.org" || r.Version != "3.1" {
		t.Errorf("cna: %+v", r)
	}
	if r := obs.Ratings[1]; r.Assessor != "134c704f-9b21-4f2e-91b3-4a467353bcc0" || r.Version != "4.0" {
		t.Errorf("adp v4: %+v", r)
	}
	if r := obs.Ratings[2]; r.Version != "3.1" || r.StatedScore != 9.8 {
		t.Errorf("adp v3.1: %+v", r)
	}
	if _, ok, _ := feed.CVEOrgObservation([]byte(`{"cveMetadata":{"state":"REJECTED"}}`)); ok {
		t.Error("a rejected record is not a revision")
	}
	if _, _, err := feed.CVEOrgObservation([]byte(`{`)); err == nil {
		t.Error("invalid json")
	}
}

func TestCVEOrgClient_FetchRecord(t *testing.T) {
	id, _ := value.NewCVEID("CVE-2024-5000")
	status := http.StatusOK
	body := cveOrgRecord
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cve/CVE-2024-5000" {
			t.Errorf("path %s", r.URL.Path)
		}
		w.Header().Set("ETag", "e1")
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, body)
	}))
	defer srv.Close()
	c := feed.NewCVEOrgClient(srv.URL+"/", srv.Client())
	obs, found, err := c.FetchRecord(context.Background(), id)
	if err != nil || !found || obs.Fetch.ETag != "e1" || obs.Fetch.HTTPStatus != http.StatusOK {
		t.Fatalf("fetch: %+v %v %v", obs.Fetch, found, err)
	}
	status = http.StatusNotFound
	if _, found, err := c.FetchRecord(context.Background(), id); found || err != nil {
		t.Errorf("404: %v %v", found, err)
	}
	status = http.StatusBadGateway
	if _, _, err := c.FetchRecord(context.Background(), id); err == nil {
		t.Error("502 must be an error")
	}
	status, body = http.StatusOK, "{"
	if _, _, err := c.FetchRecord(context.Background(), id); err == nil {
		t.Error("bad json must be an error")
	}
	if _, _, err := feed.NewCVEOrgClient("http://127.0.0.1:1", nil).FetchRecord(context.Background(), id); err == nil {
		t.Error("transport error")
	}
	if _, _, err := feed.NewCVEOrgClient("http://bad host", nil).FetchRecord(context.Background(), id); err == nil {
		t.Error("request error")
	}
	if c := feed.NewCVEOrgClient("", nil); c == nil {
		t.Error("default client")
	}
}

func TestRockyClient_SeverityWordIsObservationMetadata(t *testing.T) {
	adv := rxsaAdvisory("RLSA-2024:1", []string{"CVE-2024-6000"}, "openssl-1:3.0.7-1.el9.src.rpm")
	adv["severity"] = "SEVERITY_IMPORTANT"
	adv2 := rxsaAdvisory("RLSA-2024:2", []string{"CVE-2024-6000"}, "openssl-1:3.0.7-2.el9.src.rpm")
	adv2["severity"] = "unknown"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, rockyPage(2, adv, adv2))
	}))
	defer srv.Close()
	id, _ := value.NewCVEID("CVE-2024-6000")
	facts, err := feed.NewRockyClient(srv.URL, srv.Client()).VulnsForCVE(context.Background(), id)
	if err != nil || !facts.Found {
		t.Fatal(err, facts.Found)
	}
	obs, ok := facts.Proposal.Proposal.Observation()
	if !ok || obs.SeverityWord != "Important" || len(obs.Ratings) != 0 || obs.DocumentRef != "rocky:CVE-2024-6000" {
		t.Errorf("observation: %+v", obs)
	}
}
