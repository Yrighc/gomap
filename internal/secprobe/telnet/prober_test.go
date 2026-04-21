package telnet_test

import (
	"context"
	"testing"
	"time"

	telnetprobe "github.com/yrighc/gomap/internal/secprobe/telnet"
	"github.com/yrighc/gomap/internal/secprobe/testutil"
	"github.com/yrighc/gomap/pkg/secprobe"
)

func TestTelnetProberStopsAfterSuccess(t *testing.T) {
	server := testutil.StartFakeTelnet(t, "admin", "admin")

	prober := telnetprobe.New()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       server.Port,
		Service:    "telnet",
	}, secprobe.CredentialProbeOptions{
		Timeout:       2 * time.Second,
		StopOnSuccess: true,
	}, []secprobe.Credential{
		{Username: "admin", Password: "wrong"},
		{Username: "admin", Password: "admin"},
		{Username: "admin", Password: "later"},
	})

	if !result.Success {
		t.Fatalf("expected telnet success, got %+v", result)
	}
	if got := server.Attempts(); got != 2 {
		t.Fatalf("expected 2 telnet attempts before stopping, got %d", got)
	}
}
