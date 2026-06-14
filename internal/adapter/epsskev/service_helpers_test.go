package epsskev

import (
	"strings"
	"testing"
	"time"
)

func TestServiceHelperDefaults(t *testing.T) {
	svc := &Service{}
	if svc.batchSize() != defaultReEnrichBatchSize {
		t.Fatalf("batchSize = %d", svc.batchSize())
	}
	if svc.minRowRatio() != defaultMinEPSSRowRatio {
		t.Fatalf("minRowRatio = %f", svc.minRowRatio())
	}
	if svc.staleAfter() != defaultStaleAfter {
		t.Fatalf("staleAfter = %v", svc.staleAfter())
	}

	custom := &Service{BatchSize: 10, MinRowRatio: 0.8, StaleAfter: time.Hour}
	if custom.batchSize() != 10 || custom.minRowRatio() != 0.8 || custom.staleAfter() != time.Hour {
		t.Fatal("expected custom helper values")
	}
}

func TestBatchCount(t *testing.T) {
	if batchCount(0, 100) != 0 {
		t.Fatal("expected zero batches")
	}
	if batchCount(1001, 500) != 3 {
		t.Fatalf("batchCount = %d", batchCount(1001, 500))
	}
}

func TestNoOpMetricsInterface(t *testing.T) {
	var metrics SyncMetrics = NoOpMetrics{}
	metrics.RecordSync("epss", "success")
	metrics.RecordReEnrichBatches(2)
	metrics.SetStale(true)
}

func TestParseEPSSCSVSkipsMetadataRows(t *testing.T) {
	csv := "# comment\nCVE,epss\nCVE-2024-0001,0.1\n"
	out, err := ParseEPSSCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("out = %#v", out)
	}
}

func TestParseKEVJSONDedupesCVEs(t *testing.T) {
	body := []byte(`{"vulnerabilities":[{"cveID":"CVE-1"},{"cveID":"CVE-1"},{"cveID":""}]}`)
	out, err := ParseKEVJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0] != "CVE-1" {
		t.Fatalf("out = %#v", out)
	}
}

func TestDecompressIfGzipPlaintext(t *testing.T) {
	reader, closer, err := decompressIfGzip([]byte("plain"))
	if err != nil || closer != nil {
		t.Fatalf("reader=%v closer=%v err=%v", reader, closer, err)
	}
}

func TestDecompressIfGzipInvalidPayload(t *testing.T) {
	_, _, err := decompressIfGzip([]byte{0x1f, 0x8b, 0x00})
	if err == nil {
		t.Fatal("expected gzip error")
	}
}
