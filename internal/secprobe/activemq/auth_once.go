package activemq

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

	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

const (
	stompCommand          = "STOMP"
	stompConnectedCommand = "CONNECTED"
	stompErrorCommand     = "ERROR"
	stompAcceptVersion    = "1.2"
	optionalBannerTimeout = 50 * time.Millisecond
)

var errActiveMQAuthenticationFailed = errors.New("activemq stomp authentication failed")

type Authenticator struct {
	auth func(context.Context, strategy.Target, strategy.Credential) error
}

type stompFrame struct {
	command string
	headers map[string]string
	body    string
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
			ErrorCode:   classifyActiveMQFailure(err),
			FindingType: result.FindingTypeCredentialValid,
		}}
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success:     true,
		Username:    cred.Username,
		Password:    cred.Password,
		Evidence:    "ActiveMQ STOMP authentication succeeded",
		FindingType: result.FindingTypeCredentialValid,
	}}
}

func authWithCredential(ctx context.Context, target strategy.Target, cred strategy.Credential) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	timeout := timeoutFromContext(ctx)
	conn, err := dialActiveMQ(ctx, target, timeout)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	stopCancelWatcher := watchContextCancel(ctx, conn)
	defer stopCancelWatcher()

	deadline := time.Time{}
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
		_ = conn.SetDeadline(deadline)
	}

	reader := bufio.NewReader(conn)
	discardOptionalBanner(conn, reader, deadline)

	if err := writeSTOMPFrame(conn, stompFrame{
		command: stompCommand,
		headers: map[string]string{
			"accept-version": stompAcceptVersion,
			"host":           stompHost(target),
			"login":          cred.Username,
			"passcode":       cred.Password,
		},
	}); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}

	response, err := readSTOMPFrame(reader)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	return interpretSTOMPResponse(response)
}

func dialActiveMQ(ctx context.Context, target strategy.Target, timeout time.Duration) (net.Conn, error) {
	addr := net.JoinHostPort(target.IP, strconv.Itoa(target.Port))
	dialer := &net.Dialer{Timeout: timeout}
	return dialer.DialContext(ctx, "tcp", addr)
}

func stompHost(target strategy.Target) string {
	if host := strings.TrimSpace(target.Host); host != "" {
		return host
	}
	if ip := strings.TrimSpace(target.IP); ip != "" {
		return ip
	}
	return "localhost"
}

func discardOptionalBanner(conn net.Conn, reader *bufio.Reader, deadline time.Time) {
	bannerDeadline := time.Now().Add(optionalBannerTimeout)
	if !deadline.IsZero() && bannerDeadline.After(deadline) {
		bannerDeadline = deadline
	}
	_ = conn.SetReadDeadline(bannerDeadline)

	if _, err := reader.Peek(1); err == nil {
		_, _ = reader.ReadString('\n')
	}

	if !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
		return
	}
	_ = conn.SetDeadline(time.Time{})
}

func writeSTOMPFrame(conn net.Conn, frame stompFrame) error {
	var builder strings.Builder
	builder.WriteString(frame.command)
	builder.WriteByte('\n')
	for key, value := range frame.headers {
		builder.WriteString(key)
		builder.WriteByte(':')
		builder.WriteString(value)
		builder.WriteByte('\n')
	}
	builder.WriteByte('\n')
	builder.WriteString(frame.body)
	builder.WriteByte(0)
	_, err := io.WriteString(conn, builder.String())
	return err
}

func readSTOMPFrame(reader *bufio.Reader) (stompFrame, error) {
	command, err := reader.ReadString('\n')
	if err != nil {
		return stompFrame{}, err
	}

	headers := make(map[string]string)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return stompFrame{}, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return stompFrame{}, fmt.Errorf("invalid stomp header line %q", line)
		}
		headers[key] = value
	}

	body, err := reader.ReadBytes(0)
	if err != nil {
		return stompFrame{}, err
	}
	return stompFrame{
		command: strings.TrimSpace(command),
		headers: headers,
		body:    strings.TrimSuffix(string(body), "\x00"),
	}, nil
}

func interpretSTOMPResponse(frame stompFrame) error {
	switch strings.ToUpper(strings.TrimSpace(frame.command)) {
	case stompConnectedCommand:
		return nil
	case stompErrorCommand:
		detail := strings.TrimSpace(frame.headers["message"])
		if body := strings.TrimSpace(frame.body); body != "" {
			if detail != "" {
				detail += ": "
			}
			detail += body
		}
		if detail == "" {
			detail = "broker returned STOMP ERROR frame"
		}
		return fmt.Errorf("%w: %s", errActiveMQAuthenticationFailed, detail)
	default:
		return fmt.Errorf("unexpected stomp response command %q", frame.command)
	}
}

func classifyActiveMQFailure(err error) result.ErrorCode {
	if err == nil {
		return ""
	}

	text := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.Canceled), strings.Contains(text, "context canceled"):
		return result.ErrorCodeCanceled
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(text, "deadline exceeded"), strings.Contains(text, "timeout"), strings.Contains(text, "timed out"), strings.Contains(text, "i/o timeout"):
		return result.ErrorCodeTimeout
	case errors.Is(err, errActiveMQAuthenticationFailed),
		strings.Contains(text, "authentication failed"),
		strings.Contains(text, "invalid credentials"),
		strings.Contains(text, "access refused"),
		strings.Contains(text, "bad login"),
		strings.Contains(text, "bad password"):
		return result.ErrorCodeAuthentication
	case strings.Contains(text, "unexpected stomp response"),
		strings.Contains(text, "returned receipt without connected frame"),
		strings.Contains(text, "invalid stomp header"),
		strings.Contains(text, "broker returned"):
		return result.ErrorCodeInsufficientConfirmation
	case strings.Contains(text, "dial"),
		strings.Contains(text, "connect"),
		strings.Contains(text, "connection"),
		strings.Contains(text, "refused"),
		strings.Contains(text, "reset by peer"),
		strings.Contains(text, "broken pipe"),
		strings.Contains(text, "no route"),
		strings.Contains(text, "eof"),
		strings.Contains(text, "closed network connection"):
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

func watchContextCancel(ctx context.Context, conn net.Conn) func() {
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
