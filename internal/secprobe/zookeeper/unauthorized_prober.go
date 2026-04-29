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

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			conn.Close()
			return nil, ctx.Err()
		case <-timer.C:
			conn.Close()
			return nil, context.DeadlineExceeded
		case event, ok := <-events:
			if !ok {
				conn.Close()
				return nil, zk.ErrConnectionClosed
			}
			if event.Err != nil {
				conn.Close()
				return nil, event.Err
			}
			if event.State == zk.StateConnected || event.State == zk.StateHasSession {
				return connClient{conn: conn}, nil
			}
			if event.State == zk.StateAuthFailed || event.State == zk.StateExpired {
				conn.Close()
				if event.Err != nil {
					return nil, event.Err
				}
				return nil, errors.New(event.State.String())
			}
		}
	}
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
	case errors.Is(err, zk.ErrNoAuth):
		return core.FailureReasonAuthentication
	case isZookeeperConnectionError(err):
		return core.FailureReasonConnection
	default:
		return core.FailureReason("unknown")
	}
}

func isZookeeperConnectionError(err error) bool {
	if errors.Is(err, zk.ErrConnectionClosed) || errors.Is(err, zk.ErrClosing) || errors.Is(err, zk.ErrNoServer) {
		return true
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
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
