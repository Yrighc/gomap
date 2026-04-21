package ftp_test

import (
	"context"
	"testing"
	"time"

	ftpprobe "github.com/yrighc/gomap/internal/secprobe/ftp"
	"github.com/yrighc/gomap/internal/secprobe/testutil"
	"github.com/yrighc/gomap/pkg/secprobe"
)

func TestFTPProberFindsValidCredential(t *testing.T) {
	container := testutil.StartLinuxServer(t, testutil.LinuxServerConfig{
		Username: "testftp",
		Password: "testftp",
		Services: []string{"ftp"},
	})

	prober := ftpprobe.New()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.MappedPort("21/tcp"),
		Service:    "ftp",
	}, secprobe.CredentialProbeOptions{
		Timeout:       5 * time.Second,
		StopOnSuccess: true,
	}, []secprobe.Credential{
		{Username: "testftp", Password: "testftp"},
	})

	if !result.Success {
		t.Fatalf("expected ftp success, got %+v", result)
	}
}
