package http_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/themis-project/themis/internal/platform/auth"
	"github.com/themis-project/themis/internal/registry/adapters/store"
	"github.com/themis-project/themis/internal/registry/app"
)

func patch(t *testing.T, url, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPatch, url, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PATCH %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// An admin (here: auth off, no principal) renames; the answer is the project as it now is,
// with the same id and product.
func TestRenameProjectHTTP(t *testing.T) {
	e := seedEstate(t)
	srv := newServer(t, e.repo)
	status, raw := patch(t, srv.URL+"/projects/"+e.p1Project, `{"name":"  project-a "}`)
	if status != http.StatusOK {
		t.Fatalf("rename = %d: %s", status, raw)
	}
	var got struct {
		ID        string `json:"id"`
		ProductID string `json:"product_id"`
		Name      string `json:"name"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != e.p1Project || got.ProductID != e.p1 || got.Name != "project-a" {
		t.Errorf("renamed = %+v", got)
	}
	if e.repo.projectObjs[e.p1Project].Name() != "project-a" {
		t.Errorf("store holds %q", e.repo.projectObjs[e.p1Project].Name())
	}
}

func TestRenameProjectHTTPRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		project func(estate) string
		body    string
		err     error
		want    int
	}{
		"unknown project": {project: func(estate) string { return "no-such-project" }, body: `{"name":"x"}`, want: http.StatusNotFound},
		"gone mid-way":    {body: `{"name":"x"}`, err: store.ErrNotFound, want: http.StatusNotFound},
		"empty name":      {body: `{"name":"   "}`, want: http.StatusBadRequest},
		"bad json":        {body: `{`, want: http.StatusBadRequest},
		"name taken":      {body: `{"name":"x"}`, err: app.ErrProjectNameTaken, want: http.StatusConflict},
		"store error":     {body: `{"name":"x"}`, err: errors.New("db down"), want: http.StatusInternalServerError},
	} {
		t.Run(name, func(t *testing.T) {
			e := seedEstate(t)
			e.repo.renameErr = tc.err
			id := e.p1Project
			if tc.project != nil {
				id = tc.project(e)
			}
			before := e.repo.projectObjs[e.p1Project].Name()
			status, raw := patch(t, newServer(t, e.repo).URL+"/projects/"+id, tc.body)
			if status != tc.want {
				t.Fatalf("status = %d, want %d: %s", status, tc.want, raw)
			}
			if e.repo.projectObjs[e.p1Project].Name() != before {
				t.Error("a refused rename changed the name")
			}
		})
	}
}

// A product-scoped key may not rename, not even a project of its own product: renaming is a
// person's estate decision, and a CI key only needs find-or-create.
func TestRenameProjectNeedsAdminKey(t *testing.T) {
	e := seedEstate(t)
	before := e.repo.projectObjs[e.p1Project].Name()
	status, raw := patch(t, serverAs(t, e.repo, productKey(e.p1)).URL+"/projects/"+e.p1Project, `{"name":"x"}`)
	wantForbidden(t, "rename with a product key", status, raw)
	if e.repo.projectObjs[e.p1Project].Name() != before {
		t.Error("a refused rename changed the name")
	}

	admin := auth.Principal{KeyID: "k-2", Name: "operator", Scopes: []string{auth.ScopeAdmin}}
	if status, raw := patch(t, serverAs(t, e.repo, admin).URL+"/projects/"+e.p1Project, `{"name":"x"}`); status != http.StatusOK {
		t.Fatalf("admin rename = %d: %s", status, raw)
	}
}
