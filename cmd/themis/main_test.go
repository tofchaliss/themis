package main

import (
	"context"
	"strings"
	"testing"
)

func TestRunRoutesAdminSubcommand(t *testing.T) {
	err := run([]string{"admin"})
	if err == nil || !strings.Contains(err.Error(), "admin subcommand required") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunDefaultsToServerWithoutArgs(t *testing.T) {
	t.Setenv("THEMIS_CONFIG_PATH", t.TempDir()+"/missing.yaml")
	err := run(nil)
	if err == nil {
		t.Fatal("expected server boot error without database config")
	}
}

func TestRunUnknownAdminSubcommand(t *testing.T) {
	err := run([]string{"admin", "rotate-key"})
	if err == nil || !strings.Contains(err.Error(), "unknown admin subcommand") {
		t.Fatalf("err = %v", err)
	}
}

func TestMainDoesNotStartServerForAdminHelpPath(t *testing.T) {
	ctx := context.Background()
	_ = ctx
	err := run([]string{"admin", "create-key"})
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("err = %v", err)
	}
}
