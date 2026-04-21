package ssh_test

import (
	"context"
	"testing"
	"time"

	sshprobe "github.com/yrighc/gomap/internal/secprobe/ssh"
	"github.com/yrighc/gomap/internal/secprobe/testutil"
	"github.com/yrighc/gomap/pkg/secprobe"
)

func TestSSHProberFindsValidCredential(t *testing.T) {
	container := testutil.StartLinuxServer(t, testutil.LinuxServerConfig{
		Username: "test",
		Password: "test",
		Services: []string{"ssh"},
	})

	prober := sshprobe.New()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.MappedPort("2222/tcp"),
		Service:    "ssh",
	}, secprobe.CredentialProbeOptions{
		Timeout:       5 * time.Second,
		StopOnSuccess: true,
	}, []secprobe.Credential{
		{Username: "test", Password: "bad"},
		{Username: "test", Password: "test"},
	})

	if !result.Success {
		t.Fatalf("expected ssh success, got %+v", result)
	}
}
