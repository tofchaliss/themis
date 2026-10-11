package report

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// utf8BOM is skipped when PEEKING only. A BOM-prefixed JSON body is not valid JSON
// (RFC 8259) and is refused — but seeing past the BOM is what makes the refusal
// `malformed_body` ("we do not know what we are reading") instead of
// `unrecognised_format`, which would send the operator looking for the wrong fault.
// It is never stripped from the body: the bytes that are fingerprinted are the bytes
// that were submitted.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// jsonOpener reports the first structural byte of a JSON value — '{' for an object,
// '[' for an array, 0 for neither (which includes an empty body). It reads no
// further than that byte, so naming a 60 MB SBOM costs nothing.
func jsonOpener(body []byte) byte {
	trimmed := bytes.TrimLeft(bytes.TrimPrefix(body, utf8BOM), " \t\r\n")
	if len(trimmed) == 0 {
		return 0
	}
	switch trimmed[0] {
	case '{', '[':
		return trimmed[0]
	default:
		return 0
	}
}

// decodeObject parses a JSON object one level deep: enough to inspect which keys
// are present and what shape each value has, without decoding a whole SBOM's
// component list. A body that opens with '{' and does not parse is
// ErrMalformedBody, not ErrUnrecognisedFormat — "we do not know what we are
// reading" is the more actionable of the two (D5b row 1).
func decodeObject(body []byte) (map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, fmt.Errorf("%w: body opens as a JSON object but does not parse: %v", ErrMalformedBody, err)
	}
	return obj, nil
}

// decodeArray parses a top-level JSON array one level deep, keeping each element
// raw. Elements stay undecoded because the dialect decides what an element means.
func decodeArray(body []byte) ([]json.RawMessage, error) {
	var arr []json.RawMessage
	if err := json.Unmarshal(body, &arr); err != nil {
		return nil, fmt.Errorf("%w: body opens as a JSON array but does not parse: %v", ErrMalformedBody, err)
	}
	return arr, nil
}

// stringValue returns the string a raw JSON value holds, and whether it was one.
func stringValue(raw json.RawMessage) (string, bool) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// isArray reports whether a raw JSON value is an array.
func isArray(raw json.RawMessage) bool {
	return jsonOpener(raw) == '['
}

// isObject reports whether a raw JSON value is an object.
func isObject(raw json.RawMessage) bool {
	return jsonOpener(raw) == '{'
}

// hasKeys reports whether every named key is present in the object. Presence, not
// value: a Cortex export writes `"package_purl": null` for a component it could not
// identify, and that row is still a Cortex row (the skip rule decides its fate, not
// the detector).
func hasKeys(obj map[string]json.RawMessage, keys []string) bool {
	for _, k := range keys {
		if _, ok := obj[k]; !ok {
			return false
		}
	}
	return true
}
