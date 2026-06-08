package parser_test

import (
	"testing"

	"github.com/themis-project/themis/internal/adapter/parser"
)

func TestName(t *testing.T) {
	if parser.Name() != "parser" {
		t.Fatalf("Name() = %q, want parser", parser.Name())
	}
}
