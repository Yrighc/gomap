package httpauth

import (
	"context"
	"errors"
	"strings"

	"github.com/yrighc/gomap/pkg/secprobe/result"
)

func ClassifyTransportError(err error) result.ErrorCode {
	if err == nil {
		return ""
	}

	text := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.Canceled), strings.Contains(text, "context canceled"):
		return result.ErrorCodeCanceled
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(text, "deadline exceeded"), strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return result.ErrorCodeTimeout
	case strings.Contains(text, "dial"),
		strings.Contains(text, "connect"),
		strings.Contains(text, "refused"),
		strings.Contains(text, "connection"),
		strings.Contains(text, "tls"):
		return result.ErrorCodeConnection
	default:
		return result.ErrorCodeInsufficientConfirmation
	}
}
