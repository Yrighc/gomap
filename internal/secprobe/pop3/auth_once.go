package pop3

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

var errPOP3AuthenticationFailed = errors.New("pop3 authentication failed")

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
			ErrorCode:   classifyPOP3Failure(err),
			FindingType: result.FindingTypeCredentialValid,
		}}
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success:     true,
		Username:    cred.Username,
		Password:    cred.Password,
		Evidence:    "POP3 authentication succeeded",
		FindingType: result.FindingTypeCredentialValid,
	}}
}

func authWithCredential(ctx context.Context, target strategy.Target, cred strategy.Credential) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	timeout := timeoutFromContext(ctx)
	conn, err := dialPOP3(ctx, target, timeout)
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
	if !isPOP3OK(banner) {
		return fmt.Errorf("unexpected pop3 banner: %s", strings.TrimSpace(banner))
	}

	userResp, err := runPOP3Command(conn, reader, "USER %s\r\n", cred.Username)
	if err != nil {
		return err
	}
	if !isPOP3OK(userResp) {
		if pop3ResponseRequiresTLS(userResp) {
			return fmt.Errorf("pop3 auth requires tls: %s", strings.TrimSpace(userResp))
		}
		return fmt.Errorf("%w: %s", errPOP3AuthenticationFailed, strings.TrimSpace(userResp))
	}

	passResp, err := runPOP3Command(conn, reader, "PASS %s\r\n", cred.Password)
	if err != nil {
		return err
	}
	if !isPOP3OK(passResp) {
		if pop3ResponseRequiresTLS(passResp) {
			return fmt.Errorf("pop3 auth requires tls: %s", strings.TrimSpace(passResp))
		}
		return fmt.Errorf("%w: %s", errPOP3AuthenticationFailed, strings.TrimSpace(passResp))
	}

	// PASS 成功后凭证已经被服务器确认，QUIT 只是会话收尾。
	// 部分服务端会在认证成功后立刻断开连接，这里不把收尾失败回滚成认证失败。
	_, _ = runPOP3Command(conn, reader, "QUIT\r\n")
	return nil
}

func dialPOP3(ctx context.Context, target strategy.Target, timeout time.Duration) (net.Conn, error) {
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
	case "pop3s", "pop3/ssl":
		return true
	default:
		return target.Port == 995
	}
}

func runPOP3Command(conn net.Conn, reader *bufio.Reader, format string, args ...any) (string, error) {
	if _, err := fmt.Fprintf(conn, format, args...); err != nil {
		return "", err
	}
	return reader.ReadString('\n')
}

func isPOP3OK(line string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "+OK")
}

func pop3ResponseRequiresTLS(line string) bool {
	text := strings.ToLower(line)
	return strings.Contains(text, "starttls") ||
		strings.Contains(text, "stls") ||
		strings.Contains(text, "must use tls") ||
		strings.Contains(text, "must use ssl") ||
		strings.Contains(text, "must use stls") ||
		strings.Contains(text, "tls required") ||
		strings.Contains(text, "ssl required") ||
		strings.Contains(text, "must issue") && strings.Contains(text, "tls") ||
		strings.Contains(text, "must issue") && strings.Contains(text, "stls")
}

func classifyPOP3Failure(err error) result.ErrorCode {
	if err == nil {
		return ""
	}
	text := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.Canceled), strings.Contains(text, "context canceled"):
		return result.ErrorCodeCanceled
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(text, "deadline exceeded"), strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return result.ErrorCodeTimeout
	case pop3ResponseRequiresTLS(text):
		return result.ErrorCodeInsufficientConfirmation
	case errors.Is(err, errPOP3AuthenticationFailed), strings.Contains(text, "invalid login"), strings.Contains(text, "invalid password"), strings.Contains(text, "authentication failed"), strings.Contains(text, "auth failed"), strings.Contains(text, "login failed"), strings.Contains(text, "bad login"), strings.Contains(text, "bad password"):
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
