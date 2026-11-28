package domain

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNormalizeBuildProfile(t *testing.T) {
	got, err := NormalizeBuildProfile([]byte("{\n  \"job\": \"team/build-image\",\n  \"parameters\": {\"BRANCH\": \"release/1\", \"BASE_IMAGE_TAG\": \"latest\", \"list\": [1, {\"a\": true}]}\n}"))
	if err != nil {
		t.Fatalf("valid profile: %v", err)
	}
	if string(got) != `{"job":"team/build-image","parameters":{"BRANCH":"release/1","BASE_IMAGE_TAG":"latest","list":[1,{"a":true}]}}` {
		t.Errorf("compact form = %s", got)
	}
	if got, err := NormalizeBuildProfile([]byte(`{}`)); err != nil || string(got) != `{}` {
		t.Errorf("empty object = %s %v", got, err)
	}

	deepOK := `{"a":{"b":{"c":{"d":{"e":1}}}}}`   // five levels of objects
	tooDeep := `{"a":{"b":{"c":{"d":{"e":{}}}}}}` // a sixth
	if _, err := NormalizeBuildProfile([]byte(deepOK)); err != nil {
		t.Errorf("five levels refused: %v", err)
	}
	refused := map[string]string{
		"not json":         `{"job":`,
		"an array":         `["a"]`,
		"a string":         `"job"`,
		"null":             `null`,
		"too deep":         tooDeep,
		"too deep, arrays": `{"a":[[[[[1]]]]]}`,
		"password":         `{"password":"x"}`,
		"nested token":     `{"parameters":{"deploy":[{"GITHUB_TOKEN":"x"}]}}`,
		"api_key":          `{"Api_Key":"x"}`,
		"api-key":          `{"api-key":"x"}`,
		"apiKey":           `{"apiKey":"x"}`,
		"secret":           `{"client_secret_name":"x"}`,
		"credential":       `{"Credentials":"x"}`,
		"too large":        `{"a":"` + strings.Repeat("x", MaxBuildProfileBytes) + `"}`,
	}
	for name, raw := range refused {
		if _, err := NormalizeBuildProfile([]byte(raw)); !errors.Is(err, ErrInvalidBuildProfile) {
			t.Errorf("%s: err = %v, want ErrInvalidBuildProfile", name, err)
		}
	}
	// A VALUE is never inspected: the guard is on key names only.
	if _, err := NormalizeBuildProfile([]byte(`{"note":"the password is elsewhere"}`)); err != nil {
		t.Errorf("a value naming a secret was refused: %v", err)
	}
}

func TestBuildProfileRecords(t *testing.T) {
	at := time.Date(2026, 11, 28, 16, 0, 0, 0, time.FixedZone("x", 3600))
	rec, err := NewBuildProfileRecord(TagProject, "prj-1", []byte(` {"job": "a"} `), " alice ", " key-1 ", at)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Level != TagProject || rec.EntityID != "prj-1" || string(rec.Profile) != `{"job":"a"}` || rec.Removed ||
		rec.Actor != "alice" || rec.Via != "key-1" || !rec.At.Equal(at) || rec.At.Location() != time.UTC || rec.Revision != 0 {
		t.Errorf("record = %+v", rec)
	}
	// sha256 of the stored bytes {"job":"a"}.
	if got := rec.SHA256(); got != "69872bb3d4935ce088f9774c847face4e064164a5f653eceb2f7e5cf7f6347e4" {
		t.Errorf("sha = %q", got)
	}
	other, _ := NewBuildProfileRecord(TagProject, "prj-1", []byte(`{"job":"b"}`), "alice", "", at)
	if other.SHA256() == rec.SHA256() {
		t.Error("two different profiles share a digest")
	}

	gone, err := NewBuildProfileRemoval(TagRelease, "rel-1", "bob", "", at)
	if err != nil || !gone.Removed || gone.Profile != nil || gone.SHA256() != "" || gone.Actor != "bob" {
		t.Errorf("removal = %+v %v", gone, err)
	}

	bad := []struct {
		level BuildProfileLevel
		id    string
		actor string
		raw   string
	}{
		{TagProduct, "prod-1", "alice", `{}`},
		{TagProject, " ", "alice", `{}`},
		{TagProject, "prj-1", " ", `{}`},
		{TagProject, "prj-1", "alice", `[]`},
	}
	for _, b := range bad {
		if _, err := NewBuildProfileRecord(b.level, b.id, []byte(b.raw), b.actor, "", at); !errors.Is(err, ErrInvalidBuildProfile) {
			t.Errorf("%+v: err = %v", b, err)
		}
	}
	if _, err := NewBuildProfileRemoval(TagProduct, "prod-1", "alice", "", at); !errors.Is(err, ErrInvalidBuildProfile) {
		t.Errorf("removal at product level: %v", err)
	}
}

// D10 item 1: the Release's own profile replaces the Project's as a whole; a removed record
// states none.
func TestResolveBuildProfile(t *testing.T) {
	prj := &BuildProfileRecord{Level: TagProject, EntityID: "prj-1", Revision: 3, Profile: []byte(`{"job":"p"}`)}
	rel := &BuildProfileRecord{Level: TagRelease, EntityID: "rel-1", Revision: 1, Profile: []byte(`{"job":"r"}`)}
	removed := &BuildProfileRecord{Level: TagRelease, EntityID: "rel-1", Revision: 2, Removed: true}

	if got, ok := ResolveBuildProfile(rel, prj); !ok || got.Level != TagRelease {
		t.Errorf("own profile: %+v %v", got, ok)
	}
	if got, ok := ResolveBuildProfile(nil, prj); !ok || got.Level != TagProject || got.Revision != 3 {
		t.Errorf("inherited: %+v %v", got, ok)
	}
	if got, ok := ResolveBuildProfile(removed, prj); !ok || got.Level != TagProject {
		t.Errorf("removed own falls to the project: %+v %v", got, ok)
	}
	if _, ok := ResolveBuildProfile(removed, nil); ok {
		t.Error("removed and no project profile must be none")
	}
	if _, ok := ResolveBuildProfile(nil, nil); ok {
		t.Error("nothing stored must be none")
	}
}
