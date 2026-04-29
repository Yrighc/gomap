package zookeeper

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-zookeeper/zk"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

type zkClient interface {
	Children(path string) ([]string, *zk.Stat, error)
	Close()
}

type connClient struct {
	conn *zk.Conn
}

func (c connClient) Children(path string) ([]string, *zk.Stat, error) {
	return c.conn.Children(path)
}

func (c connClient) Close() {
	c.conn.Close()
}

var openZookeeper = func(ctx context.Context, candidate core.SecurityCandidate, timeout time.Duration) (zkClient, error) {
	host := candidate.ResolvedIP
	if host == "" {
		host = candidate.Target
	}
	addr := net.JoinHostPort(host, strconv.Itoa(candidate.Port))

	conn, events, err := zk.Connect([]string{addr}, timeout)
	if err != nil {
		return nil, err
	}
	if err := awaitZookeeperSession(ctx, timeout, events, conn.Close); err != nil {
		return nil, err
	}

	return connClient{conn: conn}, nil
}

func NewUnauthorized() core.Prober { return unauthorizedProber{} }

type unauthorizedProber struct{}

func (unauthorizedProber) Name() string { return "zookeeper-unauthorized" }

func (unauthorizedProber) Kind() core.ProbeKind { return core.ProbeKindUnauthorized }

func (unauthorizedProber) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == "zookeeper"
}

func (unauthorizedProber) Probe(ctx context.Context, candidate core.SecurityCandidate, opts core.CredentialProbeOptions, _ []core.Credential) core.SecurityResult {
	result := core.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		ProbeKind:   core.ProbeKindUnauthorized,
		FindingType: core.FindingTypeUnauthorizedAccess,
	}
	if err := ctx.Err(); err != nil {
		result.Error = err.Error()
		result.FailureReason = classifyZookeeperUnauthorizedFailure(err)
		return result
	}

	result.Stage = core.StageAttempted

	client, err := openZookeeper(ctx, candidate, opts.Timeout)
	if err != nil {
		result.Error = err.Error()
		result.FailureReason = classifyZookeeperUnauthorizedFailure(err)
		return result
	}
	defer client.Close()

	if _, _, err = client.Children("/"); err != nil {
		result.Error = err.Error()
		result.FailureReason = classifyZookeeperUnauthorizedFailure(err)
		return result
	}

	result.Success = true
	result.Stage = core.StageConfirmed
	result.Capabilities = []core.Capability{core.CapabilityReadable}
	result.Evidence = "root children readable without authentication"
	return result
}

func classifyZookeeperUnauthorizedFailure(err error) core.FailureReason {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return core.FailureReasonTimeout
	case errors.Is(err, context.Canceled):
		return core.FailureReasonCanceled
	case errors.Is(err, zk.ErrNoAuth), errors.Is(err, zk.ErrAuthFailed):
		return core.FailureReasonAuthentication
	case isZookeeperTimeoutError(err):
		return core.FailureReasonTimeout
	case isZookeeperConnectionError(err):
		return core.FailureReasonConnection
	default:
		return core.FailureReasonInsufficientConfirmation
	}
}

func isZookeeperTimeoutError(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	text := strings.ToLower(err.Error())
	return strings.Contains(text, "timeout") || strings.Contains(text, "timed out")
}

func isZookeeperConnectionError(err error) bool {
	if errors.Is(err, zk.ErrConnectionClosed) || errors.Is(err, zk.ErrClosing) || errors.Is(err, zk.ErrNoServer) || errors.Is(err, zk.ErrSessionExpired) {
		return true
	}

	var netErr net.Error
	if errors.As(err, &netErr) && !netErr.Timeout() {
		return true
	}

	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "dial"),
		strings.Contains(text, "connect"),
		strings.Contains(text, "connection"),
		strings.Contains(text, "refused"),
		strings.Contains(text, "reset by peer"),
		strings.Contains(text, "broken pipe"),
		strings.Contains(text, "no route"),
		strings.Contains(text, "closed"),
		strings.Contains(text, "eof"):
		return true
	default:
		return false
	}
}

func awaitZookeeperSession(ctx context.Context, timeout time.Duration, events <-chan zk.Event, closeConn func()) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			closeConn()
			return ctx.Err()
		case <-timer.C:
			closeConn()
			return context.DeadlineExceeded
		case event, ok := <-events:
			if !ok {
				closeConn()
				return zk.ErrConnectionClosed
			}
			if event.Err != nil {
				closeConn()
				return event.Err
			}
			switch event.State {
			case zk.StateConnected, zk.StateHasSession, zk.StateConnectedReadOnly:
				return nil
			case zk.StateAuthFailed:
				closeConn()
				return zk.ErrAuthFailed
			case zk.StateExpired:
				closeConn()
				return zk.ErrSessionExpired
			}
		}
	}
}
