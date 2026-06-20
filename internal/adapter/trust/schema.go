package trust

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schemas/*.json
var schemaFS embed.FS

var (
	schemaOnce        sync.Once
	schemaByFormat    map[string]*jsonschema.Schema
	schemaErr         error
	readSchemaFile    = schemaFS.ReadFile
	addSchemaResource = func(compiler *jsonschema.Compiler, path string, doc any) error {
		return compiler.AddResource(path, doc)
	}
)

func resetSchemasForTest() {
	schemaOnce = sync.Once{}
	schemaByFormat = nil
	schemaErr = nil
	readSchemaFile = schemaFS.ReadFile
	addSchemaResource = func(compiler *jsonschema.Compiler, path string, doc any) error {
		return compiler.AddResource(path, doc)
	}
}

var supportedSpecVersions = map[string][]string{
	"cyclonedx": {"1.4", "1.5", "1.6"},
	"spdx":      {"2.3", "3.0", "SPDX-2.3", "SPDX-3.0"},
	"openvex":   {"0.1.0", "1.0.0", "1.0.1"},
	"csaf":      {"2.0"},
}

func loadSchemas() {
	schemas, err := compileSchemaFiles(readSchemaFile, map[string]string{
		"cyclonedx": "schemas/cyclonedx.json",
		"spdx":      "schemas/spdx.json",
		"openvex":   "schemas/openvex.json",
		"csaf":      "schemas/csaf.json",
	})
	if err != nil {
		schemaErr = err
		return
	}
	schemaByFormat = schemas
}

func compileSchemaFiles(readFile func(string) ([]byte, error), files map[string]string) (map[string]*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()
	schemas := make(map[string]*jsonschema.Schema, len(files))
	for format, path := range files {
		data, err := readFile(path)
		if err != nil {
			return nil, fmt.Errorf("read schema %s: %w", path, err)
		}
		var doc any
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("parse schema %s: %w", path, err)
		}
		if err := addSchemaResource(compiler, path, doc); err != nil {
			return nil, fmt.Errorf("add schema resource %s: %w", path, err)
		}
		schema, err := compiler.Compile(path)
		if err != nil {
			return nil, fmt.Errorf("compile schema %s: %w", path, err)
		}
		schemas[format] = schema
	}
	return schemas, nil
}

func validateDocument(format string, document []byte) error {
	schemaOnce.Do(loadSchemas)
	if schemaErr != nil {
		return schemaErr
	}

	schema, ok := schemaByFormat[strings.ToLower(format)]
	if !ok {
		return fmt.Errorf("unsupported format %q", format)
	}

	var payload any
	if err := json.Unmarshal(document, &payload); err != nil {
		return fmt.Errorf("invalid json: %w", err)
	}
	if err := schema.Validate(payload); err != nil {
		return fmt.Errorf("schema validation failed: %w", err)
	}
	return nil
}

func validateSpecVersion(format, specVersion string) error {
	allowed, ok := supportedSpecVersions[strings.ToLower(format)]
	if !ok {
		return fmt.Errorf("unsupported format %q", format)
	}
	if specVersion == "" {
		return fmt.Errorf("missing spec version")
	}
	for _, version := range allowed {
		if strings.EqualFold(specVersion, version) {
			return nil
		}
	}
	return fmt.Errorf("unsupported spec version %q for format %s", specVersion, format)
}
