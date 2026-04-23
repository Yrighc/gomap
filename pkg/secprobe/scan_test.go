package secprobe

import (
	"context"
	"testing"
	"time"
)

func TestScanRejectsEmptyServices(t *testing.T) {
	got := Scan(context.Background(), ScanRequest{
		Target:  "192.0.2.10",
		Timeout: time.Second,
	})

	if got.Error == "" {
		t.Fatalf("expected validation error, got %+v", got)
	}
	if got.Target != "192.0.2.10" {
		t.Fatalf("expected target echoed back, got %+v", got)
	}
	if got.Meta.Candidates != 0 || len(got.Results) != 0 {
		t.Fatalf("expected empty result set on validation failure, got %+v", got)
	}
}
