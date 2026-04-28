package vnc

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	gvnc "github.com/mitchellh/go-vnc"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

type clientConn interface {
	Close() error
}

var dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, address)
}

var newClient = func(conn net.Conn, password string) (clientConn, error) {
	return gvnc.Client(conn, &gvnc.ClientConfig{
		Auth: []gvnc.ClientAuth{
			&gvnc.PasswordAuth{Password: password},
		},
	})
}

func New() core.Prober { return prober{} }

type prober struct{}

func (prober) Name() string { return "vnc" }

func (prober) Kind() core.ProbeKind { return core.ProbeKindCredential }

func (prober) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == "vnc"
}

func (prober) Probe(ctx context.Context, candidate core.SecurityCandidate, opts core.CredentialProbeOptions, creds []core.Credential) core.SecurityResult {
	result := core.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		ProbeKind:   core.ProbeKindCredential,
		FindingType: core.FindingTypeCredentialValid,
	}
	successResult := result
	successFound := false
	attempted := false

	addr := net.JoinHostPort(candidate.ResolvedIP, strconv.Itoa(candidate.Port))
	for _, cred := range creds {
		if err := ctx.Err(); err != nil {
			if successFound {
				return successResult
			}
			result.Error = err.Error()
			result.FailureReason = classifyVNCFailure(err)
			return result
		}
		if !attempted {
			attempted = true
			result.Stage = core.StageAttempted
		}

		conn, err := dialContext(ctx, "tcp", addr)
		if err != nil {
			result.Error = err.Error()
			result.FailureReason = classifyVNCFailure(err)
			if isTerminalContextError(err) {
				if successFound {
					return successResult
				}
				return result
			}
			continue
		}

		stopWatch := watchConnContext(ctx, conn)
		if deadline, ok := connDeadline(ctx, opts.Timeout); ok {
			_ = conn.SetDeadline(deadline)
		}

		client, err := newClient(conn, cred.Password)
		stopWatch()
		if err != nil {
			_ = conn.Close()
			result.Error = err.Error()
			result.FailureReason = classifyVNCFailure(err)
			if isTerminalContextError(err) {
				if successFound {
					return successResult
				}
				return result
			}
			continue
		}

		_ = client.Close()
		_ = conn.Close()

		successResult.Success = true
		successResult.Username = cred.Username
		successResult.Password = cred.Password
		successResult.Evidence = "VNC authentication succeeded"
		successResult.Error = ""
		successResult.Stage = core.StageConfirmed
		successResult.FailureReason = ""
		successFound = true
		if opts.StopOnSuccess {
			return successResult
		}
	}

	if successFound {
		return successResult
	}
	return result
}

func classifyVNCFailure(err error) core.FailureReason {
	if err == nil {
		return ""
	}
	if reason := ctxFailureReason(err); reason != "" {
		return reason
	}

	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "auth"),
		strings.Contains(text, "password"),
		strings.Contains(text, "security handshake failed"),
		strings.Contains(text, "no security types"):
		return core.FailureReasonAuthentication
	case strings.Contains(text, "dial"),
		strings.Contains(text, "connect"),
		strings.Contains(text, "connection"),
		strings.Contains(text, "refused"),
		strings.Contains(text, "reset by peer"),
		strings.Contains(text, "broken pipe"),
		strings.Contains(text, "no route"):
		return core.FailureReasonConnection
	default:
		return core.FailureReasonInsufficientConfirmation
	}
}

func ctxFailureReason(err error) core.FailureReason {
	text := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.Canceled), strings.Contains(text, "context canceled"):
		return core.FailureReasonCanceled
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(text, "deadline exceeded"), strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return core.FailureReasonTimeout
	default:
		return ""
	}
}

func isTerminalContextError(err error) bool {
	reason := ctxFailureReason(err)
	return reason == core.FailureReasonCanceled || reason == core.FailureReasonTimeout
}

func watchConnContext(ctx context.Context, conn net.Conn) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	return func() {
		close(done)
	}
}

func connDeadline(ctx context.Context, timeout time.Duration) (time.Time, bool) {
	if deadline, ok := ctx.Deadline(); ok {
		return deadline, true
	}
	if timeout > 0 {
		return time.Now().Add(timeout), true
	}
	return time.Time{}, false
}
