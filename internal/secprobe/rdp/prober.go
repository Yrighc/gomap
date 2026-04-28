package rdp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	grdpcore "github.com/sergei-bronnikov/grdp/core"
	"github.com/sergei-bronnikov/grdp/plugin"
	"github.com/sergei-bronnikov/grdp/protocol/nla"
	"github.com/sergei-bronnikov/grdp/protocol/pdu"
	"github.com/sergei-bronnikov/grdp/protocol/sec"
	"github.com/sergei-bronnikov/grdp/protocol/t125"
	"github.com/sergei-bronnikov/grdp/protocol/t125/gcc"
	"github.com/sergei-bronnikov/grdp/protocol/tpkt"
	"github.com/sergei-bronnikov/grdp/protocol/x224"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

func New() core.Prober { return prober{} }

type prober struct{}

type transportMode string

const (
	transportModeRDP transportMode = "rdp"
	transportModeTLS transportMode = "tls"
)

var negotiateTransport = defaultNegotiateTransport
var loginRDP = defaultLoginRDP

func (prober) Name() string { return "rdp" }

func (prober) Kind() core.ProbeKind { return core.ProbeKindCredential }

func (prober) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == "rdp"
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

	mode, err := negotiateTransport(ctx, candidate, opts)
	if err != nil {
		result.Error = err.Error()
		result.FailureReason = classifyRDPFailure(err)
		return result
	}

	for _, cred := range creds {
		if err := ctx.Err(); err != nil {
			if successFound {
				return successResult
			}
			result.Error = err.Error()
			result.FailureReason = classifyRDPFailure(err)
			return result
		}
		if !attempted {
			attempted = true
			result.Stage = core.StageAttempted
		}

		err := loginRDP(ctx, candidate, cred, opts, mode)
		if err == nil {
			successResult.Success = true
			successResult.Username = cred.Username
			successResult.Password = cred.Password
			successResult.Evidence = successEvidence(mode)
			successResult.Error = ""
			successResult.Stage = core.StageConfirmed
			successResult.FailureReason = ""
			successFound = true
			if opts.StopOnSuccess {
				return successResult
			}
			continue
		}

		result.Error = err.Error()
		result.FailureReason = classifyRDPFailure(err)
		if isTerminalContextError(err) {
			if successFound {
				return successResult
			}
			return result
		}
	}

	if successFound {
		return successResult
	}
	return result
}

func defaultNegotiateTransport(_ context.Context, candidate core.SecurityCandidate, _ core.CredentialProbeOptions) (transportMode, error) {
	hints := strings.ToLower(strings.TrimSpace(candidate.Banner + " " + candidate.Version))
	switch {
	case strings.Contains(hints, "tls"), strings.Contains(hints, "ssl"), strings.Contains(hints, "credssp"), strings.Contains(hints, "hybrid"):
		return transportModeTLS, nil
	default:
		return transportModeRDP, nil
	}
}

func defaultLoginRDP(ctx context.Context, candidate core.SecurityCandidate, cred core.Credential, opts core.CredentialProbeOptions, mode transportMode) error {
	domain, username := splitRDPUsername(cred.Username)
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(candidate.ResolvedIP, strconv.Itoa(candidate.Port)))
	if err != nil {
		return err
	}

	if deadline, ok := deadlineFromContext(ctx, timeout); ok {
		_ = conn.SetDeadline(deadline)
	}

	socket := grdpcore.NewSocketLayer(conn)
	clientTPKT := tpkt.New(socket, nla.NewNTLMv2(domain, username, cred.Password))
	x224Client := x224.New(clientTPKT)
	mcsClient := t125.NewMCSClient(x224Client, gcc.US, gcc.KT_IBM_101_102_KEYS, 0)
	secClient := sec.NewClient(mcsClient)
	pduClient := pdu.NewClient(secClient)
	channels := plugin.NewChannels(secClient)
	defer clientTPKT.Close()

	mcsClient.SetClientDesktop(800, 600)
	secClient.SetUser(username)
	secClient.SetPwd(cred.Password)
	secClient.SetDomain(domain)
	clientTPKT.SetFastPathListener(secClient)
	secClient.SetFastPathListener(pduClient)
	secClient.SetChannelSender(mcsClient)
	channels.SetChannelSender(secClient)

	readyCh := make(chan struct{}, 1)
	errCh := make(chan error, 1)

	pushErr := func(err error) {
		select {
		case errCh <- err:
		default:
		}
	}

	x224Client.On("error", pushErr)
	pduClient.On("error", pushErr)
	pduClient.On("close", func() {
		pushErr(errors.New("rdp connection closed before authentication confirmation"))
	})
	pduClient.On("ready", func() {
		select {
		case readyCh <- struct{}{}:
		default:
		}
	})

	x224Client.SetRequestedProtocol(requestedProtocol(mode))
	if err := x224Client.Connect(); err != nil {
		return fmt.Errorf("x224 connect: %w", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	select {
	case <-readyCh:
		return nil
	case err := <-errCh:
		return err
	case <-waitCtx.Done():
		return waitCtx.Err()
	}
}

func requestedProtocol(mode transportMode) uint32 {
	if mode == transportModeTLS {
		return x224.PROTOCOL_SSL
	}
	return x224.PROTOCOL_RDP
}

func successEvidence(mode transportMode) string {
	if mode == transportModeTLS {
		return "RDP authentication succeeded (TLS security)"
	}
	return "RDP authentication succeeded (standard security)"
}

func splitRDPUsername(username string) (string, string) {
	if domain, user, ok := strings.Cut(username, `\`); ok {
		return domain, user
	}
	if user, domain, ok := strings.Cut(username, "@"); ok {
		return domain, user
	}
	return "", username
}

func deadlineFromContext(ctx context.Context, timeout time.Duration) (time.Time, bool) {
	if deadline, ok := ctx.Deadline(); ok {
		return deadline, true
	}
	if timeout > 0 {
		return time.Now().Add(timeout), true
	}
	return time.Time{}, false
}

func classifyRDPFailure(err error) core.FailureReason {
	if err == nil {
		return ""
	}
	if reason := ctxFailureReason(err); reason != "" {
		return reason
	}

	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "authentication"),
		strings.Contains(text, "logon failure"),
		strings.Contains(text, "wrong password"),
		strings.Contains(text, "access denied"),
		strings.Contains(text, "credssp"),
		strings.Contains(text, "ntlm"):
		return core.FailureReasonAuthentication
	case strings.Contains(text, "dial"),
		strings.Contains(text, "connect"),
		strings.Contains(text, "connection"),
		strings.Contains(text, "refused"),
		strings.Contains(text, "reset by peer"),
		strings.Contains(text, "broken pipe"),
		strings.Contains(text, "no route"),
		strings.Contains(text, "closed before authentication"):
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
	case errors.Is(err, context.DeadlineExceeded),
		strings.Contains(text, "deadline exceeded"),
		strings.Contains(text, "timeout"),
		strings.Contains(text, "timed out"):
		return core.FailureReasonTimeout
	default:
		return ""
	}
}

func isTerminalContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
