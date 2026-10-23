package http_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/platform/auth"
	"github.com/themis-project/themis/internal/registry/adapters/http/gen"
	"github.com/themis-project/themis/internal/registry/domain"
)

func put(t *testing.T, url string, body any) (int, []byte) {
	t.Helper()
	raw, _ := json.Marshal(body)
	if s, ok := body.(string); ok {
		raw = []byte(s)
	}
	req, _ := http.NewRequest(http.MethodPut, url, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func getJSON(t *testing.T, url string, into any) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if into != nil {
		_ = json.NewDecoder(resp.Body).Decode(into)
	}
	return resp.StatusCode
}

// EDR-REMEDIATION-01 D7: tags are set per entity, a release's effective tags carry its
// project's and product's, and the list reads filter on the effective set.
func TestTags_SetReadAndFilter(t *testing.T) {
	e := seedEstate(t)
	admin := serverAs(t, e.repo, auth.Principal{KeyID: "k-a", Name: "admin", Scopes: []string{auth.ScopeAdmin}})
	_, raw := post(t, admin.URL+"/releases", map[string]string{"project_id": e.mrfProject, "version": "1.0"})
	rel := idOf(t, raw)
	_, raw = post(t, admin.URL+"/releases", map[string]string{"project_id": e.mrfProject, "version": "2.0"})
	rel2 := idOf(t, raw)
	if code, body := put(t, admin.URL+"/products/"+e.mrf+"/tags", gen.TagsPut{Tags: []string{"Team:Payments"}}); code != 200 || !strings.Contains(string(body), "team:payments") {
		t.Fatalf("product tags = %d %s", code, body)
	}
	if code, _ := put(t, admin.URL+"/projects/"+e.mrfProject+"/tags", gen.TagsPut{Tags: []string{"env:prod"}}); code != 200 {
		t.Fatalf("project tags = %d", code)
	}
	code, body := put(t, admin.URL+"/releases/"+rel+"/tags", gen.TagsPut{Tags: []string{"customer-facing"}})
	var ts gen.TagSet
	if code != 200 || json.Unmarshal(body, &ts) != nil || strings.Join(ts.Tags, ",") != "customer-facing" ||
		strings.Join(ts.Effective, ",") != "customer-facing,env:prod,team:payments" {
		t.Fatalf("release tags = %d %s", code, body)
	}
	var got gen.TagSet
	if code := getJSON(t, admin.URL+"/projects/"+e.mrfProject+"/tags", &got); code != 200 || strings.Join(got.Effective, ",") != "env:prod,team:payments" {
		t.Fatalf("project read = %d %+v", code, got)
	}
	var prods []gen.ProductView
	if getJSON(t, admin.URL+"/products?tag=team:payments", &prods); len(prods) != 1 || *prods[0].Id != e.mrf || prods[0].Tags == nil {
		t.Fatalf("product filter = %+v", prods)
	}
	var projs []gen.ProjectView
	if getJSON(t, admin.URL+"/products/"+e.mrf+"/projects?tag=env:prod", &projs); len(projs) != 1 || *projs[0].Id != e.mrfProject {
		t.Fatalf("project filter = %+v", projs)
	}
	var rels []gen.ReleaseView
	if getJSON(t, admin.URL+"/projects/"+e.mrfProject+"/releases?tag=customer-facing", &rels); len(rels) != 1 || *rels[0].Id != rel {
		t.Fatalf("release filter = %+v", rels)
	}
	if getJSON(t, admin.URL+"/projects/"+e.mrfProject+"/releases?tag=env:prod", &rels); len(rels) != 2 {
		t.Fatalf("release filter (inherited) = %+v", rels)
	}
	_ = rel2
	if getJSON(t, admin.URL+"/products?tag=nope", &prods); len(prods) != 0 {
		t.Fatalf("no match = %+v", prods)
	}
}

func TestTags_RefusalsAndErrors(t *testing.T) {
	e := seedEstate(t)
	admin := serverAs(t, e.repo, auth.Principal{KeyID: "k-a", Name: "admin", Scopes: []string{auth.ScopeAdmin}})
	_, raw := post(t, admin.URL+"/releases", map[string]string{"project_id": e.mrfProject, "version": "1.0"})
	rel := idOf(t, raw)
	// A key for the other product may not tag this one, at any level.
	other := serverAs(t, e.repo, productKey(e.oamp))
	for _, url := range []string{"/products/" + e.mrf + "/tags", "/projects/" + e.mrfProject + "/tags", "/releases/" + rel + "/tags", "/releases/ghost/tags"} {
		if code, _ := put(t, other.URL+url, gen.TagsPut{Tags: []string{"x"}}); code != http.StatusForbidden {
			t.Errorf("%s by a foreign product key = %d", url, code)
		}
	}
	// Its own product's key may.
	own := serverAs(t, e.repo, productKey(e.mrf))
	if code, _ := put(t, own.URL+"/releases/"+rel+"/tags", gen.TagsPut{Tags: []string{"x"}}); code != 200 {
		t.Fatalf("own product key = %d", code)
	}
	if code, _ := put(t, admin.URL+"/products/"+e.mrf+"/tags", gen.TagsPut{Tags: []string{"bad tag"}}); code != http.StatusBadRequest {
		t.Fatalf("bad tag = %d", code)
	}
	if code, _ := put(t, admin.URL+"/products/"+e.mrf+"/tags", "{not json"); code != http.StatusBadRequest {
		t.Fatalf("bad json = %d", code)
	}
	if code, _ := put(t, admin.URL+"/products/ghost/tags", gen.TagsPut{Tags: []string{"x"}}); code != http.StatusNotFound {
		t.Fatalf("unknown product = %d", code)
	}
	if code := getJSON(t, admin.URL+"/releases/ghost/tags", nil); code != http.StatusNotFound {
		t.Fatalf("unknown release read = %d", code)
	}
	e.repo.tagsErr = errors.New("db")
	if code := getJSON(t, admin.URL+"/products/"+e.mrf+"/tags", nil); code != http.StatusInternalServerError {
		t.Fatalf("store error read = %d", code)
	}
	for _, url := range []string{"/products", "/products/" + e.mrf + "/projects", "/projects/" + e.mrfProject + "/releases"} {
		if code := getJSON(t, admin.URL+url, nil); code != http.StatusInternalServerError {
			t.Errorf("%s with a tag store error = %d", url, code)
		}
	}
	_ = domain.TagProduct
}

func TestListTaggedReleases(t *testing.T) {
	e := seedEstate(t)
	admin := serverAs(t, e.repo, auth.Principal{KeyID: "k-a", Name: "admin", Scopes: []string{auth.ScopeAdmin}})
	_, raw := post(t, admin.URL+"/releases", map[string]string{"project_id": e.mrfProject, "version": "1.0"})
	rel := idOf(t, raw)
	if code, _ := put(t, admin.URL+"/releases/"+rel+"/tags", gen.TagsPut{Tags: []string{"env:prod"}}); code != 200 {
		t.Fatal(code)
	}
	var rels []gen.ReleaseView
	if code := getJSON(t, admin.URL+"/tagged-releases?tag=env:prod", &rels); code != 200 || len(rels) != 1 || *rels[0].Id != rel {
		t.Fatalf("tagged = %d %+v", code, rels)
	}
	if code := getJSON(t, admin.URL+"/tagged-releases?tag=bad%20tag", nil); code != http.StatusBadRequest {
		t.Fatalf("bad tag = %d", code)
	}
	e.repo.tagsErr2 = errors.New("db")
	if code := getJSON(t, admin.URL+"/tagged-releases?tag=env:prod", nil); code != http.StatusInternalServerError {
		t.Fatalf("store error = %d", code)
	}
}
