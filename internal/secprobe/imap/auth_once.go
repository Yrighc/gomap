package imap

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

var errIMAPAuthenticationFailed = errors.New("imap authentication failed")

type Authenticator struct {
	auth func(context.Context, strategy.Target, strategy.Credential) error
}

func NewAuthenticator(auth func(context.Context, strategy.Target, strategy.Credential) error) Authenticator {
	if auth == nil {
		auth = authWithCredential
	}
	return Authenticator{auth: auth}
}

func (a Authenticator) AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) registrybridge.Attempt {
	if err := a.auth(ctx, target, cred); err != nil {
		return registrybridge.Attempt{Result: result.Attempt{
			Error:       err.Error(),
			ErrorCode:   classifyIMAPFailure(err),
			FindingType: result.FindingTypeCredentialValid,
		}}
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success:     true,
		Username:    cred.Username,
		Password:    cred.Password,
		Evidence:    "IMAP authentication succeeded",
		FindingType: result.FindingTypeCredentialValid,
	}}
}

func authWithCredential(ctx context.Context, target strategy.Target, cred strategy.Credential) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	timeout := timeoutFromContext(ctx)
	conn, err := dialIMAP(ctx, target, timeout)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(strings.TrimSpace(banner), "* OK") {
		return fmt.Errorf("unexpected imap banner: %s", strings.TrimSpace(banner))
	}

	if _, err := fmt.Fprintf(conn, "a001 LOGIN %s %s\r\n", quoteIMAPString(cred.Username), quoteIMAPString(cred.Password)); err != nil {
		return err
	}
	loginResponse, err := readTaggedResponse(reader, "a001")
	if err != nil {
		return err
	}
	if !taggedResponseOK(loginResponse, "a001") {
		if responseRequiresTLS(loginResponse) {
			return fmt.Errorf("imap login requires tls: %s", strings.TrimSpace(loginResponse))
		}
		return fmt.Errorf("%w: %s", errIMAPAuthenticationFailed, strings.TrimSpace(loginResponse))
	}

	if _, err := fmt.Fprint(conn, "a002 LOGOUT\r\n"); err != nil {
		return err
	}
	_, _ = readTaggedResponse(reader, "a002")
	return nil
}

func dialIMAP(ctx context.Context, target strategy.Target, timeout time.Duration) (net.Conn, error) {
	addr := net.JoinHostPort(target.IP, strconv.Itoa(target.Port))
	dialer := &net.Dialer{Timeout: timeout}
	if shouldUseTLS(target) {
		serverName := target.Host
		if serverName == "" {
			serverName = target.IP
		}
		return tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
		})
	}
	return dialer.DialContext(ctx, "tcp", addr)
}

func shouldUseTLS(target strategy.Target) bool {
	switch strings.ToLower(target.Protocol) {
	case "imaps", "imap/ssl":
		return true
	default:
		return target.Port == 993
	}
}

func quoteIMAPString(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + replacer.Replace(value) + `"`
}

func readTaggedResponse(reader *bufio.Reader, tag string) (string, error) {
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		if strings.HasPrefix(strings.TrimSpace(line), tag+" ") {
			return line, nil
		}
	}
}

func taggedResponseOK(line, tag string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), strings.ToUpper(tag+" OK "))
}

func responseRequiresTLS(line string) bool {
	text := strings.ToLower(line)
	return strings.Contains(text, "starttls") ||
		strings.Contains(text, "must issue a starttls command first") ||
		strings.Contains(text, "tls required") ||
		strings.Contains(text, "privacyrequired")
}

func classifyIMAPFailure(err error) result.ErrorCode {
	if err == nil {
		return ""
	}
	text := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.Canceled), strings.Contains(text, "context canceled"):
		return result.ErrorCodeCanceled
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(text, "deadline exceeded"), strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return result.ErrorCodeTimeout
	case responseRequiresTLS(text):
		return result.ErrorCodeInsufficientConfirmation
	case errors.Is(err, errIMAPAuthenticationFailed), strings.Contains(text, "authenticationfailed"), strings.Contains(text, "auth"), strings.Contains(text, "invalid credentials"), strings.Contains(text, "login failed"), strings.Contains(text, "password"), strings.Contains(text, "username"):
		return result.ErrorCodeAuthentication
	case strings.Contains(text, "dial"), strings.Contains(text, "connect"), strings.Contains(text, "connection"), strings.Contains(text, "refused"), strings.Contains(text, "reset by peer"), strings.Contains(text, "no route"), strings.Contains(text, "tls"):
		return result.ErrorCodeConnection
	default:
		return result.ErrorCodeInsufficientConfirmation
	}
}

func timeoutFromContext(ctx context.Context) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		if timeout := time.Until(deadline); timeout > 0 {
			return timeout
		}
	}
	return 0
}
