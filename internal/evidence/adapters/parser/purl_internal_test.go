package parser

import "testing"

func TestEcosystemFromPURL(t *testing.T) {
	cases := map[string]struct {
		in   string
		want string
		ok   bool
	}{
		"noScheme":  {"npm/foo@1", "", false},
		"emptyBody": {"pkg:", "", false},
		"withSlash": {"pkg:deb/debian/openssl@3.0.11", "deb", true},
		"typeAtVer": {"pkg:golang@1.2.3", "golang", true},
		"leadSlash": {"pkg:/foo", "", false},
	}
	for name, c := range cases {
		got, ok := ecosystemFromPURL(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: got (%q,%v), want (%q,%v)", name, got, ok, c.want, c.ok)
		}
	}
}

func TestNameVersionFromPURL(t *testing.T) {
	cases := map[string]struct {
		in       string
		wantName string
		wantVer  string
	}{
		"noScheme":     {"npm/foo@1", "", ""},
		"noSlash":      {"pkg:golang", "", ""},
		"trailingSlash": {"pkg:deb/", "", ""},
		"nameAndVer":   {"pkg:deb/debian/openssl@3.0.11", "debian/openssl", "3.0.11"},
		"nameOnly":     {"pkg:deb/foo", "foo", ""},
		"qualifiers":   {"pkg:deb/foo@1.0?arch=amd64", "foo", "1.0"},
		"percentName":  {"pkg:deb/libstdc%2B%2B@1", "libstdc++", "1"},
	}
	for name, c := range cases {
		gotName, gotVer := nameVersionFromPURL(c.in)
		if gotName != c.wantName || gotVer != c.wantVer {
			t.Errorf("%s: got (%q,%q), want (%q,%q)", name, gotName, gotVer, c.wantName, c.wantVer)
		}
	}
}

func TestStripVersionQualifiers(t *testing.T) {
	for in, want := range map[string]string{
		"1.0":          "1.0",
		"1.0?arch=x86": "1.0",
		"1.0#frag":     "1.0",
	} {
		if got := stripVersionQualifiers(in); got != want {
			t.Errorf("strip(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDecodeSegment(t *testing.T) {
	if got := decodeSegment("libstdc%2B%2B"); got != "libstdc++" {
		t.Errorf("decode valid = %q", got)
	}
	if got := decodeSegment("%zz"); got != "%zz" { // invalid encoding falls back to raw
		t.Errorf("decode invalid = %q, want %q", got, "%zz")
	}
}
