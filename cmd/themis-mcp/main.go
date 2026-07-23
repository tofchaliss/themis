// Command themis-mcp is a Model Context Protocol (MCP) server that exposes the
// Themis security-intelligence platform to LLM clients as a set of tools.
//
// It is a standalone API client: it talks to a running Themis server over its
// REST API (/api/v1) and holds no database access of its own. Configure the
// target with THEMIS_BASE_URL (default http://localhost:8080) and authenticate
// with THEMIS_API_KEY.
//
// Transports:
//
//	themis-mcp                 # stdio (default) — for Claude Code/Desktop et al.
//	themis-mcp --http :9000    # streamable HTTP — for a networked/shared gateway
//
// On stdio, only the MCP protocol is written to stdout; all logs go to stderr.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const version = "0.1.0"

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func main() {
	defaultBaseURL := firstNonEmpty(
		os.Getenv("THEMIS_MCP_BASE_URL"),
		os.Getenv("THEMIS_BASE_URL"),
		"http://localhost:8080",
	)

	var (
		httpAddr string
		baseURL  string
		readOnly bool
		timeout  time.Duration
	)
	flag.StringVar(&httpAddr, "http", "", "serve streamable HTTP on this address (e.g. :9000) instead of stdio")
	flag.StringVar(&baseURL, "base-url", defaultBaseURL, "base URL of the Themis server (env THEMIS_BASE_URL)")
	flag.BoolVar(&readOnly, "read-only", os.Getenv("THEMIS_MCP_READ_ONLY") == "1", "expose only read-only tools; hide every mutating tool (env THEMIS_MCP_READ_ONLY=1)")
	flag.DurationVar(&timeout, "timeout", 60*time.Second, "per-request HTTP timeout")
	flag.Parse()

	apiKey := os.Getenv("THEMIS_API_KEY")
	if apiKey == "" {
		log.Println("warning: THEMIS_API_KEY is not set; only /healthz and /readyz will work until a key is provided")
	}

	c := newClient(baseURL, apiKey, timeout)

	newServer := func() *mcp.Server {
		s := mcp.NewServer(&mcp.Implementation{Name: "themis", Version: version}, nil)
		registerTools(s, c, readOnly)
		return s
	}

	ctx := context.Background()

	if httpAddr != "" {
		handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return newServer() }, nil)
		log.Printf("themis-mcp %s: serving streamable HTTP on %s → %s (read_only=%v)", version, httpAddr, baseURL, readOnly)
		if err := http.ListenAndServe(httpAddr, handler); err != nil {
			fmt.Fprintf(os.Stderr, "themis-mcp: http server error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	log.Printf("themis-mcp %s: serving on stdio → %s (read_only=%v)", version, baseURL, readOnly)
	if err := newServer().Run(ctx, &mcp.StdioTransport{}); err != nil {
		fmt.Fprintf(os.Stderr, "themis-mcp: server error: %v\n", err)
		os.Exit(1)
	}
}
