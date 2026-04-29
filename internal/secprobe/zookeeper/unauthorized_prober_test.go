package zookeeper

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-zookeeper/zk"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

type fakeZKClient struct {
	children     []string
	childrenErr  error
	childrenPath string
	closed       bool
}

func (f *fakeZKClient) Children(path string) ([]string, *zk.Stat, error) {
	f.childrenPath = path
	if f.childrenErr != nil {
		return nil, nil, f.childrenErr
	}
	return append([]string(nil), f.children...), nil, nil
}

func (f *fakeZKClient) Close() {
	f.closed = true
}

func TestZookeeperUnauthorizedProberFindsReadableRoot(t *testing.T) {
	original := openZookeeper
	t.Cleanup(func() { openZookeeper = original })

	client := &fakeZKClient{children: []string{"zookeeper", "app"}}
	openZookeeper = func(context.Context, core.SecurityCandidate, time.Duration) (zkClient, error) {
		return client, nil
	}

	result := NewUnauthorized().Probe(context.Background(), core.SecurityCandidate{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       2181,
		Service:    "zookeeper",
	}, core.CredentialProbeOptions{Timeout: time.Second}, nil)

	if !result.Success {
		t.Fatalf("expected zookeeper unauthorized success, got %+v", result)
	}
	if result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed stage, got %+v", result)
	}
	if result.FindingType != core.FindingTypeUnauthorizedAccess {
		t.Fatalf("expected unauthorized finding type, got %+v", result)
	}
	if len(result.Capabilities) != 1 || result.Capabilities[0] != core.CapabilityReadable {
		t.Fatalf("expected readable capability, got %+v", result)
	}
	if client.childrenPath != "/" {
		t.Fatalf("expected root children read, got path %q", client.childrenPath)
	}
	if !client.closed {
		t.Fatal("expected zookeeper client to be closed")
	}
}

func TestZookeeperUnauthorizedProberClassifiesAuthenticationFailure(t *testing.T) {
	original := openZookeeper
	t.Cleanup(func() { openZookeeper = original })

	client := &fakeZKClient{childrenErr: zk.ErrNoAuth}
	openZookeeper = func(context.Context, core.SecurityCandidate, time.Duration) (zkClient, error) {
		return client, nil
	}

	result := NewUnauthorized().Probe(context.Background(), core.SecurityCandidate{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       2181,
		Service:    "zookeeper",
	}, core.CredentialProbeOptions{Timeout: time.Second}, nil)

	if result.Success {
		t.Fatalf("expected authentication failure, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonAuthentication {
		t.Fatalf("expected authentication failure reason, got %+v", result)
	}
}

func TestZookeeperUnauthorizedProberClassifiesConnectionFailure(t *testing.T) {
	original := openZookeeper
	t.Cleanup(func() { openZookeeper = original })

	openZookeeper = func(context.Context, core.SecurityCandidate, time.Duration) (zkClient, error) {
		return nil, errors.New("dial tcp 127.0.0.1:2181: connection refused")
	}

	result := NewUnauthorized().Probe(context.Background(), core.SecurityCandidate{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       2181,
		Service:    "zookeeper",
	}, core.CredentialProbeOptions{Timeout: time.Second}, nil)

	if result.FailureReason != core.FailureReasonConnection {
		t.Fatalf("expected connection failure reason, got %+v", result)
	}
}

func TestZookeeperUnauthorizedProberClassifiesCanceledContextBeforeProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := NewUnauthorized().Probe(ctx, core.SecurityCandidate{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       2181,
		Service:    "zookeeper",
	}, core.CredentialProbeOptions{Timeout: time.Second}, nil)

	if result.FailureReason != core.FailureReasonCanceled {
		t.Fatalf("expected canceled failure reason, got %+v", result)
	}
}

func TestZookeeperUnauthorizedProberClassifiesDeadlineExceededBeforeProbe(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	result := NewUnauthorized().Probe(ctx, core.SecurityCandidate{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       2181,
		Service:    "zookeeper",
	}, core.CredentialProbeOptions{Timeout: time.Second}, nil)

	if result.FailureReason != core.FailureReasonTimeout {
		t.Fatalf("expected timeout failure reason, got %+v", result)
	}
}

func TestAwaitZookeeperSessionTreatsConnectedReadOnlyAsSuccess(t *testing.T) {
	events := make(chan zk.Event, 1)
	events <- zk.Event{State: zk.StateConnectedReadOnly}

	closed := false
	err := awaitZookeeperSession(context.Background(), time.Second, events, func() {
		closed = true
	})

	if err != nil {
		t.Fatalf("expected read-only session success, got %v", err)
	}
	if closed {
		t.Fatal("expected connection to stay open on read-only success")
	}
}

func TestAwaitZookeeperSessionMapsAuthFailedToAuthenticationError(t *testing.T) {
	events := make(chan zk.Event, 1)
	events <- zk.Event{State: zk.StateAuthFailed}

	closed := false
	err := awaitZookeeperSession(context.Background(), time.Second, events, func() {
		closed = true
	})

	if !errors.Is(err, zk.ErrAuthFailed) {
		t.Fatalf("expected zk.ErrAuthFailed, got %v", err)
	}
	if classifyZookeeperUnauthorizedFailure(err) != core.FailureReasonAuthentication {
		t.Fatalf("expected authentication failure reason, got %v", classifyZookeeperUnauthorizedFailure(err))
	}
	if !closed {
		t.Fatal("expected connection to close on auth failure")
	}
}

func TestAwaitZookeeperSessionMapsExpiredToConnectionError(t *testing.T) {
	events := make(chan zk.Event, 1)
	events <- zk.Event{State: zk.StateExpired}

	closed := false
	err := awaitZookeeperSession(context.Background(), time.Second, events, func() {
		closed = true
	})

	if !errors.Is(err, zk.ErrSessionExpired) {
		t.Fatalf("expected zk.ErrSessionExpired, got %v", err)
	}
	if classifyZookeeperUnauthorizedFailure(err) != core.FailureReasonConnection {
		t.Fatalf("expected connection failure reason, got %v", classifyZookeeperUnauthorizedFailure(err))
	}
	if !closed {
		t.Fatal("expected connection to close on expired session")
	}
}
