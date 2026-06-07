package main

import (
	"context"
	"fmt"
	"os"

	"github.com/themis-project/themis/internal/infrastructure/http"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	return httpserver.Run(context.Background())
}
