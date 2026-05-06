package template

import (
	"context"
	"testing"

	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

func TestUnauthorizedTemplateCheckerMatchesMemcachedStatsResponse(t *testing.T) {
	checker := NewUnauthorizedChecker(UnauthorizedTemplate{
		Name:      "memcached",
		Transport: "tcp",
		Request:   "stats\r\n",
		Matchers:  Matchers{Contains: []string{"STAT version ", "\r\nEND\r\n"}},
		Success: Success{
			FindingType: "unauthorized_access",
			Evidence:    "stats returned version without authentication",
		},
	}, func(context.Context, strategy.Target, string) (string, error) {
		return "STAT version 1.6.21\r\nEND\r\n", nil
	})

	out := checker.CheckUnauthorizedOnce(context.Background(), strategy.Target{
		Host: "demo", IP: "127.0.0.1", Port: 11211, Protocol: "memcached",
	})

	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}
	if out.Result.FindingType != result.FindingTypeUnauthorizedAccess {
		t.Fatalf("unexpected finding type: %+v", out.Result)
	}
}

func TestUnauthorizedTemplateCheckerRejectsUnsupportedTransport(t *testing.T) {
	checker := NewUnauthorizedChecker(UnauthorizedTemplate{Name: "bad", Transport: "udp"}, nil)
	out := checker.CheckUnauthorizedOnce(context.Background(), strategy.Target{Protocol: "bad"})
	if out.Result.ErrorCode != result.ErrorCodeInsufficientConfirmation {
		t.Fatalf("expected insufficient confirmation, got %+v", out.Result)
	}
}

var _ registrybridge.UnauthorizedChecker = UnauthorizedChecker{}
