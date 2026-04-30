package registry

import (
	"context"

	"github.com/yrighc/gomap/internal/secprobe/core"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

type Attempt struct {
	Result result.Attempt
	Legacy core.SecurityResult
}

type CredentialAuthenticator interface {
	AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) Attempt
}

type UnauthorizedChecker interface {
	CheckUnauthorizedOnce(ctx context.Context, target strategy.Target) Attempt
}

type Enricher interface {
	EnrichOnce(ctx context.Context, target strategy.Target, attempt Attempt) Attempt
}
