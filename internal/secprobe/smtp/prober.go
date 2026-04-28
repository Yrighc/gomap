package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	stdsmtp "net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

type smtpClient interface {
	Extension(string) (bool, string)
	StartTLS(*tls.Config) error
	Auth(stdsmtp.Auth) error
	Quit() error
	Close() error
}

type smtpDialPlan struct {
	implicitTLS   bool
	allowStartTLS bool
}

var dialSMTPClient = defaultDialSMTPClient
var dialImplicitTLSContext = defaultDialImplicitTLSContext

func New() core.Prober { return prober{} }

type prober struct{}

func (prober) Name() string { return "smtp" }

func (prober) Kind() core.ProbeKind { return core.ProbeKindCredential }

func (prober) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == "smtp"
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
	plan := buildDialPlan(candidate)
	for _, cred := range creds {
		if err := ctx.Err(); err != nil {
			if successFound {
				return successResult
			}
			result.Error = err.Error()
			result.FailureReason = classifySMTPFailure(err)
			return result
		}
		if !attempted {
			attempted = true
			result.Stage = core.StageAttempted
		}

		for _, mechanism := range []string{"PLAIN", "LOGIN"} {
			attemptResult, attemptedMechanism, err := attemptSMTPAuth(ctx, candidate, addr, plan, opts.Timeout, cred, mechanism)
			if !attemptedMechanism {
				continue
			}

			if err == nil {
				successResult.Success = true
				successResult.Username = cred.Username
				successResult.Password = cred.Password
				successResult.Evidence = "SMTP authentication succeeded"
				successResult.Error = ""
				successResult.Stage = core.StageConfirmed
				successResult.FailureReason = ""
				successFound = true
				if opts.StopOnSuccess {
					return successResult
				}
				break
			}

			result.Error = attemptResult.Error
			result.FailureReason = attemptResult.FailureReason
			if isTerminalSMTPFailure(result.FailureReason) {
				if successFound {
					return successResult
				}
				return result
			}
		}

		if !successFound || successResult.Username != cred.Username || successResult.Password != cred.Password {
			if result.Error == "" {
				result.Error = "smtp server does not advertise AUTH PLAIN or AUTH LOGIN"
				result.FailureReason = core.FailureReasonInsufficientConfirmation
			}
		}
	}

	if successFound {
		return successResult
	}
	return result
}

func buildDialPlan(candidate core.SecurityCandidate) smtpDialPlan {
	if candidate.Port == 465 {
		return smtpDialPlan{implicitTLS: true}
	}
	return smtpDialPlan{allowStartTLS: true}
}

func defaultDialSMTPClient(ctx context.Context, addr string, plan smtpDialPlan, timeout time.Duration) (smtpClient, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: timeout}
	if plan.implicitTLS {
		conn, err := dialImplicitTLSContext(ctx, "tcp", addr, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		})
		if err != nil {
			return nil, err
		}
		_ = conn.SetDeadline(time.Now().Add(timeout))

		client, err := stdsmtp.NewClient(conn, host)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		return client, nil
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if deadlineConn, ok := conn.(interface{ SetDeadline(time.Time) error }); ok {
		_ = deadlineConn.SetDeadline(time.Now().Add(timeout))
	}

	client, err := stdsmtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if !plan.allowStartTLS {
		return client, nil
	}

	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		}); err != nil {
			_ = client.Close()
			return nil, err
		}
	}

	return client, nil
}

func defaultDialImplicitTLSContext(ctx context.Context, network, addr string, config *tls.Config) (net.Conn, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config:    config,
	}
	return dialer.DialContext(ctx, network, addr)
}

func attemptSMTPAuth(ctx context.Context, candidate core.SecurityCandidate, addr string, plan smtpDialPlan, timeout time.Duration, cred core.Credential, mechanism string) (core.SecurityResult, bool, error) {
	result := core.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		ProbeKind:   core.ProbeKindCredential,
		FindingType: core.FindingTypeCredentialValid,
	}

	client, err := dialSMTPClient(ctx, addr, plan, timeout)
	if err != nil {
		result.Error = err.Error()
		result.FailureReason = classifySMTPFailure(err)
		return result, true, err
	}
	defer closeSMTPClient(client)

	mechanisms := advertisedSMTPAuthMechanisms(client)
	if _, ok := mechanisms[mechanism]; !ok {
		return result, false, nil
	}

	switch mechanism {
	case "PLAIN":
		err = client.Auth(stdsmtp.PlainAuth("", cred.Username, cred.Password, authHost(candidate)))
	case "LOGIN":
		err = client.Auth(&loginAuth{username: cred.Username, password: cred.Password, state: loginStateUsername})
	default:
		return result, false, nil
	}
	if err != nil {
		result.Error = err.Error()
		result.FailureReason = classifySMTPFailure(err)
		return result, true, err
	}

	return result, true, nil
}

func advertisedSMTPAuthMechanisms(client smtpClient) map[string]struct{} {
	mechanisms := map[string]struct{}{}
	ok, params := client.Extension("AUTH")
	if !ok {
		return mechanisms
	}
	for _, token := range strings.Fields(strings.ToUpper(params)) {
		mechanisms[token] = struct{}{}
	}
	return mechanisms
}

func authHost(candidate core.SecurityCandidate) string {
	if candidate.Target != "" {
		return candidate.Target
	}
	return candidate.ResolvedIP
}

func closeSMTPClient(client smtpClient) {
	if client == nil {
		return
	}
	_ = client.Quit()
	_ = client.Close()
}

func classifySMTPFailure(err error) core.FailureReason {
	if err == nil {
		return ""
	}
	if reason := ctxFailureReason(err); reason != "" {
		return reason
	}

	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "auth"), strings.Contains(text, "authentication"), strings.Contains(text, "535"), strings.Contains(text, "534"), strings.Contains(text, "credentials"), strings.Contains(text, "username"), strings.Contains(text, "password"):
		return core.FailureReasonAuthentication
	case strings.Contains(text, "dial"), strings.Contains(text, "connect"), strings.Contains(text, "connection"), strings.Contains(text, "refused"), strings.Contains(text, "reset by peer"), strings.Contains(text, "no route"), strings.Contains(text, "handshake"):
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

func isTerminalSMTPFailure(reason core.FailureReason) bool {
	return reason == core.FailureReasonCanceled || reason == core.FailureReasonTimeout || reason == core.FailureReasonConnection
}

type loginAuth struct {
	username string
	password string
	state    loginAuthState
}

type loginAuthState int

const (
	loginStateUsername loginAuthState = iota
	loginStatePassword
	loginStateDone
)

func (a *loginAuth) Start(_ *stdsmtp.ServerInfo) (string, []byte, error) {
	a.state = loginStateUsername
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		a.state = loginStateDone
		return nil, nil
	}

	challenge := strings.ToLower(strings.TrimSpace(string(fromServer)))
	switch a.state {
	case loginStateUsername:
		a.state = loginStatePassword
		return []byte(a.username), nil
	case loginStatePassword:
		a.state = loginStateDone
		return []byte(a.password), nil
	default:
		if strings.Contains(challenge, "password") {
			return []byte(a.password), nil
		}
		return nil, nil
	}
}
