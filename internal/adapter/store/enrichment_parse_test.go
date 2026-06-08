package store

import "testing"

func TestParseVEXAssertionsOpenVEX(t *testing.T) {
	raw := []byte(`{
		"statements": [{
			"vulnerability": {"name": "CVE-2024-0001"},
			"products": [{"@id": "pkg:npm/lodash@1.0.0"}],
			"status": "not_affected",
			"justification": "component_not_present"
		}]
	}`)
	assertions, err := parseVEXAssertions("openvex", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(assertions) != 1 || assertions[0].CVEID != "CVE-2024-0001" {
		t.Fatalf("assertions = %+v", assertions)
	}
}

func TestParseVEXAssertionsInvalidJSON(t *testing.T) {
	if _, err := parseVEXAssertions("openvex", []byte("{")); err == nil {
		t.Fatal("expected error")
	}
}
