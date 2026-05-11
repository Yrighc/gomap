package httpauth

import (
	"context"
	"errors"
	"testing"

	"github.com/yrighc/gomap/pkg/secprobe/result"
)

func TestClassifyMapsStandardHTTPFailures(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want result.ErrorCode
	}{
		{name: "timeout", err: context.DeadlineExceeded, want: result.ErrorCodeTimeout},
		{name: "canceled", err: context.Canceled, want: result.ErrorCodeCanceled},
		{name: "connection", err: errors.New("dial tcp 127.0.0.1:80: connect: connection refused"), want: result.ErrorCodeConnection},
		{name: "tls", err: errors.New("tls: handshake failure"), want: result.ErrorCodeConnection},
		{name: "fallback", err: errors.New("unexpected upstream response"), want: result.ErrorCodeInsufficientConfirmation},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyTransportError(tt.err); got != tt.want {
				t.Fatalf("want %q got %q", tt.want, got)
			}
		})
	}
}
