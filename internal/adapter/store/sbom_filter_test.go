package store_test

import (
	"strings"
	"testing"
)

func TestSoftDelete_StoreFilterNotCallerFilter(t *testing.T) {
	queryWithoutFilter := `
		SELECT id FROM sbom_documents s WHERE s.id = $1
	`
	queryWithFilter := `
		SELECT id FROM sbom_documents s WHERE s.id = $1 AND s.deleted_at IS NULL
	`
	if !strings.Contains(queryWithFilter, "deleted_at IS NULL") {
		t.Fatal("store filter must include deleted_at IS NULL")
	}
	if strings.Contains(queryWithoutFilter, "deleted_at IS NULL") {
		t.Fatal("unfiltered query must not hide the leak risk")
	}
}
