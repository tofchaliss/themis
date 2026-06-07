package domain

import "testing"

func TestJobTypes(t *testing.T) {
	if JobTypeIngestSBOM != "ingest_sbom" {
		t.Fatalf("JobTypeIngestSBOM = %q", JobTypeIngestSBOM)
	}
}

func TestJobStruct(t *testing.T) {
	job := Job{ID: "1", Type: JobTypeIngestVEX, Payload: []byte("x")}
	if job.ID != "1" || job.Type != JobTypeIngestVEX {
		t.Fatalf("unexpected job: %+v", job)
	}
}
