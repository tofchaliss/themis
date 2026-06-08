//go:build tools

package tools

import (
	_ "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen"
	_ "github.com/roblaszczak/go-cleanarch"
	_ "golang.org/x/tools/cmd/deadcode"
)
