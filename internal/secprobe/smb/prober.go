package smb

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/hirochachacha/go-smb2"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

func New() core.Prober { return prober{} }

type prober struct{}

type smbSession interface {
	Mount(string) error
	Logoff() error
	Authenticated() bool
}

type managedSMBSession struct {
	conn    net.Conn
	session *smb2.Session
}

// go-smb2 v1.1.0 keeps guest/null session state in internal sessionFlags.
// We mirror the relevant bits here so we can reject sessions that mounted IPC$
// without authenticating the supplied credential.
const (
	smb2SessionFlagIsGuest uint16 = 1 << iota
	smb2SessionFlagIsNull
)

var errSMBGuestOrNullSession = errors.New("smb guest/null session does not confirm credential validity")

func (s *managedSMBSession) Mount(share string) error {
	fs, err := s.session.Mount(share)
	if err != nil {
		return err
	}
	return fs.Umount()
}

func (s *managedSMBSession) Logoff() error {
	var logoffErr error
	if s.session != nil {
		logoffErr = s.session.Logoff()
	}
	if s.conn != nil {
		if closeErr := s.conn.Close(); logoffErr == nil {
			logoffErr = closeErr
		}
	}
	return logoffErr
}

func (s *managedSMBSession) Authenticated() bool {
	flags, ok := smbSessionFlags(s.session)
	if !ok {
		return false
	}
	return flags&(smb2SessionFlagIsGuest|smb2SessionFlagIsNull) == 0
}

var dialSMBSession = defaultDialSMBSession

var openSMBConn = func(ctx context.Context, network, address string, timeout time.Duration, cred core.Credential) (smbSession, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	if deadline, ok := deadlineFromContext(ctx, timeout); ok {
		_ = conn.SetDeadline(deadline)
	}

	domain, username := splitSMBUsername(cred.Username)
	session, err := (&smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     username,
			Password: cred.Password,
			Domain:   domain,
		},
	}).DialContext(ctx, conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	return &managedSMBSession{
		conn:    conn,
		session: session.WithContext(ctx),
	}, nil
}

func (prober) Name() string { return "smb" }

func (prober) Kind() core.ProbeKind { return core.ProbeKindCredential }

func (prober) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == "smb"
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
	timeout := effectiveTimeout(opts.Timeout)

	for _, cred := range creds {
		if err := ctx.Err(); err != nil {
			if successFound {
				return successResult
			}
			result.Error = err.Error()
			result.FailureReason = classifySMBFailure(err)
			return result
		}
		if !attempted {
			attempted = true
			result.Stage = core.StageAttempted
		}

		session, err := dialSMBSession(ctx, addr, cred, timeout)
		if err == nil {
			successResult.Success = true
			successResult.Username = cred.Username
			successResult.Password = cred.Password
			successResult.Evidence = `SMB authentication succeeded by mounting IPC$`
			successResult.Error = ""
			successResult.Stage = core.StageConfirmed
			successResult.FailureReason = ""
			successFound = true
			_ = session.Logoff()
			if opts.StopOnSuccess {
				return successResult
			}
			continue
		}

		result.Error = err.Error()
		result.FailureReason = classifySMBFailure(err)
		if session != nil {
			_ = session.Logoff()
		}
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

func defaultDialSMBSession(ctx context.Context, address string, cred core.Credential, timeout time.Duration) (smbSession, error) {
	dialCtx := ctx
	var cancel context.CancelFunc
	if _, ok := ctx.Deadline(); !ok && timeout > 0 {
		dialCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	session, err := openSMBConn(dialCtx, "tcp", address, timeout, cred)
	if err != nil {
		return nil, err
	}

	if err := session.Mount("IPC$"); err != nil {
		_ = session.Logoff()
		return nil, err
	}
	if !session.Authenticated() {
		_ = session.Logoff()
		return nil, errSMBGuestOrNullSession
	}
	return session, nil
}

func smbSessionFlags(session *smb2.Session) (uint16, bool) {
	if session == nil {
		return 0, false
	}

	sessionValue := reflect.ValueOf(session)
	if sessionValue.Kind() != reflect.Pointer || sessionValue.IsNil() {
		return 0, false
	}

	sessionStruct := sessionValue.Elem()
	innerSession := sessionStruct.FieldByName("s")
	if !innerSession.IsValid() || innerSession.IsNil() {
		return 0, false
	}

	innerSession = reflect.NewAt(innerSession.Type(), unsafe.Pointer(innerSession.UnsafeAddr())).Elem()
	innerValue := innerSession.Elem()
	sessionFlags := innerValue.FieldByName("sessionFlags")
	if !sessionFlags.IsValid() || sessionFlags.Kind() != reflect.Uint16 {
		return 0, false
	}

	sessionFlags = reflect.NewAt(sessionFlags.Type(), unsafe.Pointer(sessionFlags.UnsafeAddr())).Elem()
	return uint16(sessionFlags.Uint()), true
}

func effectiveTimeout(timeout time.Duration) time.Duration {
	if timeout > 0 {
		return timeout
	}
	return 5 * time.Second
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

func splitSMBUsername(username string) (string, string) {
	if domain, user, ok := strings.Cut(username, `\`); ok {
		return domain, user
	}
	if user, domain, ok := strings.Cut(username, "@"); ok {
		return domain, user
	}
	return "", username
}

func classifySMBFailure(err error) core.FailureReason {
	if err == nil {
		return ""
	}
	if reason := ctxFailureReason(err); reason != "" {
		return reason
	}

	var transportErr *smb2.TransportError
	if errors.As(err, &transportErr) {
		return core.FailureReasonConnection
	}

	var responseErr *smb2.ResponseError
	if errors.As(err, &responseErr) {
		return classifySMBResponse(responseErr.Error())
	}

	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "authentication"),
		strings.Contains(text, "logon"),
		strings.Contains(text, "access denied"),
		strings.Contains(text, "password"),
		strings.Contains(text, "account restriction"),
		strings.Contains(text, "logon type not granted"),
		strings.Contains(text, "must change"):
		return core.FailureReasonAuthentication
	case strings.Contains(text, "dial"),
		strings.Contains(text, "connect"),
		strings.Contains(text, "connection"),
		strings.Contains(text, "refused"),
		strings.Contains(text, "broken pipe"),
		strings.Contains(text, "reset by peer"),
		strings.Contains(text, "no route"):
		return core.FailureReasonConnection
	default:
		return core.FailureReasonInsufficientConfirmation
	}
}

func classifySMBResponse(text string) core.FailureReason {
	lowered := strings.ToLower(text)
	switch {
	case strings.Contains(lowered, "status_logon_failure"),
		strings.Contains(lowered, "status_access_denied"),
		strings.Contains(lowered, "status_account_restriction"),
		strings.Contains(lowered, "status_invalid_logon_hours"),
		strings.Contains(lowered, "status_password_restriction"),
		strings.Contains(lowered, "status_password_expired"),
		strings.Contains(lowered, "status_password_must_change"),
		strings.Contains(lowered, "status_logon_type_not_granted"):
		return core.FailureReasonAuthentication
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
