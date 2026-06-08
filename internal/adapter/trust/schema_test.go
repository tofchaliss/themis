package trust

import (
	"errors"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestValidateDocumentInvalidJSON(t *testing.T) {
	if err := validateDocument("cyclonedx", []byte("{")); err == nil {
		t.Fatal("expected invalid json error")
	}
}

func TestValidateDocumentUnsupportedFormat(t *testing.T) {
	if err := validateDocument("not-real", []byte("{}")); err == nil {
		t.Fatal("expected unsupported format error")
	}
}

func TestLoadSchemasError(t *testing.T) {
	resetSchemasForTest()
	readSchemaFile = func(string) ([]byte, error) {
		return nil, errors.New("read failed")
	}
	loadSchemas()
	if schemaErr == nil {
		t.Fatal("expected schema load error")
	}
	resetSchemasForTest()
}

func TestValidateDocumentSchemaLoadError(t *testing.T) {
	resetSchemasForTest()
	readSchemaFile = func(string) ([]byte, error) {
		return nil, errors.New("read failed")
	}
	if err := validateDocument("cyclonedx", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5"}`)); err == nil {
		t.Fatal("expected schema load error")
	}
	resetSchemasForTest()
}

func TestCompileSchemaFilesAddResourceError(t *testing.T) {
	_, err := compileSchemaFiles(func(string) ([]byte, error) {
		return []byte(`"string-schema"`), nil
	}, map[string]string{
		"broken": "schemas/broken.json",
	})
	if err == nil {
		t.Fatal("expected add resource error")
	}
}

func TestCompileSchemaFilesSuccess(t *testing.T) {
	schemas, err := compileSchemaFiles(readSchemaFile, map[string]string{
		"cyclonedx": "schemas/cyclonedx.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if schemas["cyclonedx"] == nil {
		t.Fatal("expected cyclonedx schema")
	}
}

func TestCompileSchemaFilesMissingFile(t *testing.T) {
	_, err := compileSchemaFiles(readSchemaFile, map[string]string{
		"missing": "schemas/does-not-exist.json",
	})
	if err == nil {
		t.Fatal("expected read error")
	}
}

func TestCompileSchemaFilesInvalidJSON(t *testing.T) {
	_, err := compileSchemaFiles(func(string) ([]byte, error) {
		return []byte("{"), nil
	}, map[string]string{
		"broken": "schemas/broken.json",
	})
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestCompileSchemaFilesInvalidSchemaDocument(t *testing.T) {
	_, err := compileSchemaFiles(func(string) ([]byte, error) {
		return []byte(`{"type":"not-valid-root-type"}`), nil
	}, map[string]string{
		"broken": "schemas/broken.json",
	})
	if err == nil {
		t.Fatal("expected compile error")
	}
}

func TestCompileSchemaFilesAddResourceHookError(t *testing.T) {
	original := addSchemaResource
	addSchemaResource = func(*jsonschema.Compiler, string, any) error {
		return errors.New("add resource failed")
	}
	t.Cleanup(func() { addSchemaResource = original })

	_, err := compileSchemaFiles(readSchemaFile, map[string]string{
		"broken": "schemas/cyclonedx.json",
	})
	if err == nil {
		t.Fatal("expected add resource error")
	}
}

func TestCompileSchemaFilesLoadsAllEmbeddedSchemas(t *testing.T) {
	schemas, err := compileSchemaFiles(readSchemaFile, map[string]string{
		"cyclonedx": "schemas/cyclonedx.json",
		"spdx":      "schemas/spdx.json",
		"openvex":   "schemas/openvex.json",
		"csaf":      "schemas/csaf.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(schemas) != 4 {
		t.Fatalf("schema count = %d, want 4", len(schemas))
	}
}

func TestCompileSchemaFilesInvalidResourceType(t *testing.T) {
	_, err := compileSchemaFiles(func(string) ([]byte, error) {
		return []byte(`42`), nil
	}, map[string]string{
		"broken": "schemas/broken.json",
	})
	if err == nil {
		t.Fatal("expected schema compile error")
	}
}
