package ftp_test

import (
	"context"
	"errors"
	"testing"
	"time"

	ftpprobe "github.com/yrighc/gomap/internal/secprobe/ftp"
	"github.com/yrighc/gomap/internal/secprobe/testutil"
	"github.com/yrighc/gomap/pkg/secprobe"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

func TestFTPAuthenticatorAuthenticateOnce(t *testing.T) {
	auth := ftpprobe.NewAuthenticator(func(_ context.Context, _ strategy.Target, cred strategy.Credential) error {
		if cred.Username == "admin" && cred.Password == "admin" {
			return nil
		}
		return errors.New("530 Login incorrect")
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "demo",
		IP:       "127.0.0.1",
		Port:     21,
		Protocol: "ftp",
	}, strategy.Credential{Username: "admin", Password: "admin"})

	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}
	if out.Result.FindingType != result.FindingTypeCredentialValid {
		t.Fatalf("unexpected finding type: %+v", out.Result)
	}
}

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
