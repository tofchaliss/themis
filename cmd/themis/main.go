package main

import (
	"context"
	"fmt"
	"os"

	"github.com/themis-project/themis/internal/infrastructure/cli"
	httpserver "github.com/themis-project/themis/internal/infrastructure/http"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 && args[0] == "admin" {
		return cli.RunAdmin(context.Background(), args[1:])
	}
	return httpserver.Run(context.Background())
}
