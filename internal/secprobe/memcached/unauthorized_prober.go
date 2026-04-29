package memcached

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

func NewUnauthorized() core.Prober { return unauthorizedProber{} }

type unauthorizedProber struct{}

func (unauthorizedProber) Name() string { return "memcached-unauthorized" }

func (unauthorizedProber) Kind() core.ProbeKind { return core.ProbeKindUnauthorized }

func (unauthorizedProber) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == "memcached"
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
		result.FailureReason = classifyMemcachedUnauthorizedFailure(err)
		return result
	}

	host := candidate.ResolvedIP
	if host == "" {
		host = candidate.Target
	}
	addr := net.JoinHostPort(host, strconv.Itoa(candidate.Port))
	dialer := &net.Dialer{Timeout: opts.Timeout}

	result.Stage = core.StageAttempted

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		result.Error = err.Error()
		result.FailureReason = classifyMemcachedUnauthorizedFailure(err)
		return result
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else if opts.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(opts.Timeout))
	}

	if _, err := conn.Write([]byte("stats\r\n")); err != nil {
		result.Error = err.Error()
		result.FailureReason = classifyMemcachedUnauthorizedFailure(err)
		return result
	}

	version, err := readStatsVersion(conn)
	if err != nil {
		result.Error = err.Error()
		result.FailureReason = classifyMemcachedUnauthorizedFailure(err)
		return result
	}
	if version == "" {
		result.Error = "stats response missing version"
		result.FailureReason = core.FailureReasonInsufficientConfirmation
		return result
	}

	result.Success = true
	result.Stage = core.StageConfirmed
	result.Capabilities = []core.Capability{core.CapabilityReadable}
	result.Evidence = "stats returned version without authentication"
	return result
}
func readStatsVersion(conn net.Conn) (string, error) {
	reader := bufio.NewReader(conn)
	var version string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}

		line = strings.TrimSpace(line)
		switch {
		case line == "END":
			return version, nil
		case strings.HasPrefix(line, "STAT version "):
			version = strings.TrimSpace(strings.TrimPrefix(line, "STAT version "))
		case line == "":
			continue
		case strings.HasPrefix(line, "ERROR"), strings.HasPrefix(line, "CLIENT_ERROR"), strings.HasPrefix(line, "SERVER_ERROR"):
			return "", fmt.Errorf("memcached stats rejected: %s", line)
		}
	}
}

func classifyMemcachedUnauthorizedFailure(err error) core.FailureReason {
	if err == nil {
		return ""
	}
	if reason := ctxFailureReason(err); reason != "" {
		return reason
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return core.FailureReasonConnection
	}

	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "auth"), strings.Contains(text, "authentication"), strings.Contains(text, "unauthorized"), strings.Contains(text, "forbidden"):
		return core.FailureReasonAuthentication
	case strings.Contains(text, "dial"), strings.Contains(text, "connect"), strings.Contains(text, "connection"), strings.Contains(text, "refused"), strings.Contains(text, "reset by peer"), strings.Contains(text, "no route"), strings.Contains(text, "broken pipe"):
		return core.FailureReasonConnection
	default:
		return core.FailureReasonInsufficientConfirmation
	}
}

func ctxFailureReason(err error) core.FailureReason {
	text := strings.ToLower(err.Error())
	switch {
	case err == context.Canceled, strings.Contains(text, "context canceled"):
		return core.FailureReasonCanceled
	case err == context.DeadlineExceeded, strings.Contains(text, "deadline exceeded"), strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return core.FailureReasonTimeout
	default:
		return ""
	}
}
