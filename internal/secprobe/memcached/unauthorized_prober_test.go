package memcached_test

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	memcachedprobe "github.com/yrighc/gomap/internal/secprobe/memcached"
	"github.com/yrighc/gomap/internal/secprobe/testutil"
	"github.com/yrighc/gomap/pkg/secprobe"
)

func TestMemcachedUnauthorizedProberDetectsOpenMemcached(t *testing.T) {
	container := testutil.StartMemcachedNoAuth(t)

	prober := memcachedprobe.NewUnauthorized()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "memcached",
	}, secprobe.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	}, nil)

	if !result.Success {
		t.Fatalf("expected memcached unauthorized success, got %+v", result)
	}
	if result.ProbeKind != secprobe.ProbeKindUnauthorized {
		t.Fatalf("expected unauthorized probe kind, got %+v", result)
	}
	if result.FindingType != secprobe.FindingTypeUnauthorizedAccess {
		t.Fatalf("expected unauthorized finding type, got %+v", result)
	}
	if result.Evidence != "stats returned version without authentication" {
		t.Fatalf("expected deterministic memcached evidence, got %+v", result)
	}
	if result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed stage, got %+v", result)
	}
	if len(result.Capabilities) != 1 || result.Capabilities[0] != core.CapabilityReadable {
		t.Fatalf("expected readable capability, got %+v", result)
	}
}

func TestMemcachedUnauthorizedProberRequiresVersionForConfirmation(t *testing.T) {
	address := startMemcachedStatsServer(t, "STAT pid 7\r\nEND\r\n")
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("convert port: %v", err)
	}

	prober := memcachedprobe.NewUnauthorized()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     host,
		ResolvedIP: host,
		Port:       port,
		Service:    "memcached",
	}, secprobe.CredentialProbeOptions{
		Timeout: 2 * time.Second,
	}, nil)

	if result.Success {
		t.Fatalf("expected missing version confirmation to fail, got %+v", result)
	}
	if result.Stage != core.StageAttempted {
		t.Fatalf("expected attempted stage when stats are readable but inconclusive, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonInsufficientConfirmation {
		t.Fatalf("expected insufficient confirmation, got %+v", result)
	}
}

func TestMemcachedUnauthorizedProberDoesNotMarkAttemptedWhenContextCanceledBeforeProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	prober := memcachedprobe.NewUnauthorized()
	result := prober.Probe(ctx, secprobe.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       11211,
		Service:    "memcached",
	}, secprobe.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	}, nil)

	if result.Stage != "" {
		t.Fatalf("expected empty stage before any probe attempt, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonCanceled {
		t.Fatalf("expected canceled failure reason, got %+v", result)
	}
}

func startMemcachedStatsServer(t *testing.T, response string) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()

				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				line, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimSpace(line) != "stats" {
					return
				}
				_, _ = conn.Write([]byte(response))
			}(conn)
		}
	}()

	return listener.Addr().String()
}
