package elasticsearch

import (
	"context"
	"fmt"

	"github.com/yrighc/gomap/internal/secprobe/core"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

var elasticsearchEnrichmentRequest = func(ctx context.Context, result core.SecurityResult, _ core.CredentialProbeOptions) (string, string, error) {
	attempt, err := authenticateOnce(ctx, strategy.Target{
		Host:     result.Target,
		IP:       result.ResolvedIP,
		Port:     result.Port,
		Protocol: result.Service,
	}, strategy.Credential{
		Username: result.Username,
		Password: result.Password,
	})
	if err != nil {
		return "", "", err
	}

	return "GET " + authenticatePath, fmt.Sprintf("200 OK\nusername: %s", attempt.Result.Username), nil
}

func Enrich(ctx context.Context, result core.SecurityResult, opts core.CredentialProbeOptions) core.SecurityResult {
	enrichCtx := ctx
	cancel := func() {}
	if opts.Timeout > 0 {
		enrichCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
	}
	defer cancel()

	request, response, err := elasticsearchEnrichmentRequest(enrichCtx, result, opts)
	if err != nil {
		result.Enrichment = map[string]any{"error": err.Error()}
		return result
	}

	result.Enrichment = map[string]any{"payload": request + "\n\n" + response}
	return result
}

func stubElasticsearchEnrichmentRequest(fn func(context.Context, core.SecurityResult, core.CredentialProbeOptions) (string, string, error)) func() {
	previous := elasticsearchEnrichmentRequest
	elasticsearchEnrichmentRequest = fn
	return func() {
		elasticsearchEnrichmentRequest = previous
	}
}
