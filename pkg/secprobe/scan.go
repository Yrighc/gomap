package secprobe

import (
	"context"
	"fmt"
	"strings"
	"time"
)

var scanRun = func(ctx context.Context, candidates []SecurityCandidate, opts CredentialProbeOptions) RunResult {
	return Run(ctx, candidates, opts)
}

func Scan(ctx context.Context, req ScanRequest) ScanResult {
	if strings.TrimSpace(req.Target) == "" {
		return ScanResult{Error: "target is required"}
	}
	candidates, err := buildScanCandidates(req)
	if err != nil {
		return ScanResult{
			Target:     req.Target,
			ResolvedIP: req.ResolvedIP,
			Error:      err.Error(),
		}
	}

	opts := CredentialProbeOptions{
		Concurrency:        req.Concurrency,
		Timeout:            req.Timeout,
		StopOnSuccess:      req.StopOnSuccess,
		EnableEnrichment:   req.EnableEnrichment,
		EnableUnauthorized: req.EnableUnauthorized,
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 10
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}

	run := scanRun(ctx, candidates, opts)
	return ScanResult{
		Target:     req.Target,
		ResolvedIP: req.ResolvedIP,
		Meta:       run.Meta,
		Results:    run.Results,
	}
}

func buildScanCandidates(req ScanRequest) ([]SecurityCandidate, error) {
	if len(req.Services) == 0 {
		return nil, fmt.Errorf("services is required")
	}

	host := scanHost(req.Target, req.ResolvedIP)
	out := make([]SecurityCandidate, 0, len(req.Services))
	for _, item := range req.Services {
		if item.Port <= 0 {
			return nil, fmt.Errorf("invalid service port %d", item.Port)
		}

		service := NormalizeServiceName(item.Service, item.Port)
		if service == "" {
			return nil, fmt.Errorf("unsupported service %q on port %d", item.Service, item.Port)
		}

		out = append(out, SecurityCandidate{
			Target:     req.Target,
			ResolvedIP: host,
			Port:       item.Port,
			Service:    service,
			Version:    item.Version,
			Banner:     item.Banner,
		})
	}
	return out, nil
}

func scanHost(target, resolvedIP string) string {
	if strings.TrimSpace(resolvedIP) != "" {
		return resolvedIP
	}
	return target
}

func stubScanRunner(fn func(context.Context, []SecurityCandidate, CredentialProbeOptions) RunResult) func() {
	previous := scanRun
	scanRun = fn
	return func() {
		scanRun = previous
	}
}
