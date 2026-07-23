package main

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strconv"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerTools wires every Themis tool onto the server. Read-only tools are
// always registered; mutating tools are registered only when readOnly is false.
func registerTools(s *mcp.Server, c *client, readOnly bool) {
	registerReadTools(s, c)
	registerPromptsAndResources(s, c)
	if !readOnly {
		registerWriteTools(s, c)
	}
}

// --- result / annotation helpers -------------------------------------------

// jsonText renders a raw JSON body as pretty-printed text content and, when the
// body is a JSON object, also as StructuredContent so MCP hosts get a typed
// value rather than only a text blob.
func jsonText(raw json.RawMessage) (*mcp.CallToolResult, any, error) {
	res := &mcp.CallToolResult{}
	var pretty bytes.Buffer
	if json.Indent(&pretty, raw, "", "  ") == nil {
		res.Content = []mcp.Content{&mcp.TextContent{Text: pretty.String()}}
	} else {
		res.Content = []mcp.Content{&mcp.TextContent{Text: string(raw)}}
	}
	// StructuredContent must marshal to a JSON object, so only set it for objects.
	var structured map[string]any
	if json.Unmarshal(raw, &structured) == nil && structured != nil {
		res.StructuredContent = structured
	}
	return res, nil, nil
}

func boolPtr(b bool) *bool { return &b }

// readOnlyHints marks a tool as never modifying Themis.
func readOnlyHints() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{ReadOnlyHint: true, Title: ""}
}

// additiveHints marks a tool that writes but only adds (never destroys) data.
func additiveHints() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{DestructiveHint: boolPtr(false)}
}

// destructiveHints marks a tool that changes finding state or removes data —
// clients may prompt for confirmation before calling it.
func destructiveHints() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{DestructiveHint: boolPtr(true)}
}

// --- query / path helpers --------------------------------------------------

func pageQuery(cursor string, limit int) url.Values {
	q := url.Values{}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	return q
}

// effectiveLimit defaults an unset limit to 50. The product/project/version
// vulnerability routes have no server-side default (unlike the others), so the
// tool always sends one to avoid an empty page.
func effectiveLimit(limit int) int {
	if limit <= 0 {
		return 50
	}
	return limit
}

func esc(s string) string { return url.PathEscape(s) }
