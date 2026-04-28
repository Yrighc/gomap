package vnc

import (
	"context"
	"crypto/des"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

const (
	rfbMessageLength    = 12
	securityTypeNone    = 1
	securityTypeVNCAuth = 2

	vncAuthOK     = 0
	vncAuthFailed = 1
)

type rfbVersion struct {
	major int
	minor int
}

var dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, address)
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

		err := probeCredential(ctx, addr, opts.Timeout, cred.Password)
		if err == nil {
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
			continue
		}

		result.Error = err.Error()
		result.FailureReason = classifyVNCFailure(err)
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

func probeCredential(ctx context.Context, address string, timeout time.Duration, password string) error {
	conn, err := dialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer conn.Close()

	stopWatch := watchConnContext(ctx, conn)
	defer stopWatch()

	if deadline, ok := connDeadline(ctx, timeout); ok {
		_ = conn.SetDeadline(deadline)
	}

	version, err := negotiateProtocolVersion(conn)
	if err != nil {
		return err
	}
	if _, err := readSecuritySelection(conn, version); err != nil {
		return err
	}
	if err := performPasswordAuth(conn, password); err != nil {
		return err
	}
	return readAuthStatus(conn, version)
}

func negotiateProtocolVersion(conn net.Conn) (rfbVersion, error) {
	buf := make([]byte, rfbMessageLength)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return rfbVersion{}, err
	}

	version, err := parseProtocolVersion(buf)
	if err != nil {
		return rfbVersion{}, err
	}

	supported, err := supportedProtocolVersion(version)
	if err != nil {
		return rfbVersion{}, err
	}

	if _, err := conn.Write([]byte(formatProtocolVersion(supported))); err != nil {
		return rfbVersion{}, err
	}
	return supported, nil
}

func parseProtocolVersion(msg []byte) (rfbVersion, error) {
	var version rfbVersion
	if len(msg) < rfbMessageLength {
		return rfbVersion{}, fmt.Errorf("protocol version message too short")
	}
	if _, err := fmt.Sscanf(string(msg), "RFB %03d.%03d\n", &version.major, &version.minor); err != nil {
		return rfbVersion{}, fmt.Errorf("parse protocol version: %w", err)
	}
	return version, nil
}

func supportedProtocolVersion(version rfbVersion) (rfbVersion, error) {
	if version.major != 3 {
		return rfbVersion{}, fmt.Errorf("unsupported rfb version %d.%d", version.major, version.minor)
	}
	switch version.minor {
	case 3, 7, 8:
		return version, nil
	default:
		return rfbVersion{}, fmt.Errorf("unsupported rfb version 3.%d", version.minor)
	}
}

func formatProtocolVersion(version rfbVersion) string {
	return fmt.Sprintf("RFB %03d.%03d\n", version.major, version.minor)
}

func readSecuritySelection(conn net.Conn, version rfbVersion) (uint8, error) {
	if version.minor == 3 {
		return readSecurityType33(conn)
	}
	return readSecurityTypes37Plus(conn)
}

func readSecurityType33(conn net.Conn) (uint8, error) {
	var securityType uint32
	if err := binary.Read(conn, binary.BigEndian, &securityType); err != nil {
		return 0, err
	}
	if securityType == 0 {
		return 0, errors.New("vnc server reported no security type")
	}
	if securityType != securityTypeVNCAuth {
		return 0, fmt.Errorf("no supported security type: %d", securityType)
	}
	return uint8(securityType), nil
}

func readSecurityTypes37Plus(conn net.Conn) (uint8, error) {
	var count uint8
	if err := binary.Read(conn, binary.BigEndian, &count); err != nil {
		return 0, err
	}
	if count == 0 {
		reason, err := readFailureReason(conn)
		if err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("vnc server reported no security types: %s", reason)
	}

	types := make([]byte, count)
	if _, err := io.ReadFull(conn, types); err != nil {
		return 0, err
	}

	for _, securityType := range types {
		if securityType != securityTypeVNCAuth {
			continue
		}
		if err := binary.Write(conn, binary.BigEndian, securityType); err != nil {
			return 0, err
		}
		return securityType, nil
	}

	return 0, fmt.Errorf("no supported security type: %v", types)
}

func performPasswordAuth(conn net.Conn, password string) error {
	challenge := make([]byte, 16)
	if _, err := io.ReadFull(conn, challenge); err != nil {
		return err
	}

	response, err := encryptResponse(password, challenge)
	if err != nil {
		return err
	}
	_, err = conn.Write(response)
	return err
}

func encryptResponse(password string, challenge []byte) ([]byte, error) {
	if len(challenge) != 16 {
		return nil, fmt.Errorf("unexpected challenge length %d", len(challenge))
	}

	block, err := des.NewCipher(vncPasswordKey(password))
	if err != nil {
		return nil, err
	}

	response := make([]byte, len(challenge))
	block.Encrypt(response[:8], challenge[:8])
	block.Encrypt(response[8:], challenge[8:])
	return response, nil
}

func vncPasswordKey(password string) []byte {
	key := make([]byte, 8)
	for i := 0; i < len(password) && i < len(key); i++ {
		key[i] = reverseBits(password[i])
	}
	return key
}

func reverseBits(b byte) byte {
	var reversed byte
	for i := 0; i < 8; i++ {
		reversed <<= 1
		reversed |= b & 1
		b >>= 1
	}
	return reversed
}

func readAuthStatus(conn net.Conn, version rfbVersion) error {
	var status uint32
	if err := binary.Read(conn, binary.BigEndian, &status); err != nil {
		return err
	}

	switch status {
	case vncAuthOK:
		return nil
	case vncAuthFailed:
		reason := "authentication failed"
		if version.minor >= 8 {
			if detail, err := readFailureReason(conn); err == nil && detail != "" {
				reason = detail
			}
		}
		return errors.New(reason)
	default:
		return fmt.Errorf("authentication status %d", status)
	}
}

func readFailureReason(conn net.Conn) (string, error) {
	var length uint32
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return "", err
	}
	if length == 0 {
		return "", nil
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", err
	}
	return string(buf), nil
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
	case strings.Contains(text, "authentication failed"),
		strings.Contains(text, "invalid password"),
		strings.Contains(text, "bad password"):
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
