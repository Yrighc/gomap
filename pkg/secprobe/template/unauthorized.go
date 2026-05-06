package template

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

type exchangeFunc func(context.Context, strategy.Target, string) (string, error)

type UnauthorizedChecker struct {
	tpl      UnauthorizedTemplate
	exchange exchangeFunc
}

func NewUnauthorizedChecker(tpl UnauthorizedTemplate, exchange exchangeFunc) UnauthorizedChecker {
	if exchange == nil {
		exchange = exchangeTCP
	}
	return UnauthorizedChecker{tpl: tpl, exchange: exchange}
}

func (c UnauthorizedChecker) CheckUnauthorizedOnce(ctx context.Context, target strategy.Target) registrybridge.Attempt {
	if c.tpl.Transport != "tcp" {
		return registrybridge.Attempt{Result: result.Attempt{
			Error:       "unsupported unauthorized template transport",
			ErrorCode:   result.ErrorCodeInsufficientConfirmation,
			FindingType: result.FindingTypeUnauthorizedAccess,
		}}
	}

	reply, err := c.exchange(ctx, target, c.tpl.Request)
	if err != nil {
		return registrybridge.Attempt{Result: result.Attempt{
			Error:       err.Error(),
			ErrorCode:   classifyTemplateNetworkFailure(err),
			FindingType: result.FindingTypeUnauthorizedAccess,
		}}
	}
	if !containsAll(reply, c.tpl.Matchers.Contains) {
		return registrybridge.Attempt{Result: result.Attempt{
			Error:       "unauthorized template match failed",
			ErrorCode:   result.ErrorCodeInsufficientConfirmation,
			FindingType: result.FindingTypeUnauthorizedAccess,
		}}
	}

	findingType := result.FindingTypeUnauthorizedAccess
	if parsed, ok := result.ParseFindingType(c.tpl.Success.FindingType); ok {
		findingType = parsed
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success:     true,
		Evidence:    c.tpl.Success.Evidence,
		FindingType: findingType,
	}}
}

func exchangeTCP(ctx context.Context, target strategy.Target, request string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	host := target.IP
	if host == "" {
		host = target.Host
	}

	timeout := timeoutFromContext(ctx)
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(target.Port)))
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()

	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
	if _, err := conn.Write([]byte(request)); err != nil {
		return "", err
	}

	reply, err := io.ReadAll(conn)
	if err != nil {
		return "", err
	}
	return string(reply), nil
}

func containsAll(reply string, needles []string) bool {
	for _, needle := range needles {
		if !strings.Contains(reply, needle) {
			return false
		}
	}
	return true
}

func classifyTemplateNetworkFailure(err error) result.ErrorCode {
	if err == nil {
		return ""
	}

	text := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.Canceled), strings.Contains(text, "context canceled"):
		return result.ErrorCodeCanceled
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(text, "deadline exceeded"), strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return result.ErrorCodeTimeout
	case strings.Contains(text, "dial"), strings.Contains(text, "connect"), strings.Contains(text, "connection"), strings.Contains(text, "refused"), strings.Contains(text, "reset by peer"), strings.Contains(text, "no route"), strings.Contains(text, "broken pipe"), strings.Contains(text, "eof"):
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
