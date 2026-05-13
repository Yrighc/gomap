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
	candidates, unsupported, err := buildScanCandidates(req)
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
		opts.Timeout = time.Second
	}

	run := scanRun(ctx, candidates, opts)
	results := mergeScanResults(req, run.Results, unsupported)
	meta := run.Meta
	meta.Candidates = len(req.Services)
	meta.Skipped += len(unsupported)
	return ScanResult{
		Target:     req.Target,
		ResolvedIP: req.ResolvedIP,
		Meta:       meta,
		Results:    results,
	}
}

func buildScanCandidates(req ScanRequest) ([]SecurityCandidate, map[int]SecurityResult, error) {
	if len(req.Services) == 0 {
		return nil, nil, fmt.Errorf("services is required")
	}

	host := scanHost(req.Target, req.ResolvedIP)
	out := make([]SecurityCandidate, 0, len(req.Services))
	unsupported := make(map[int]SecurityResult)
	for i, item := range req.Services {
		if item.Port <= 0 {
			return nil, nil, fmt.Errorf("invalid service port %d", item.Port)
		}

		service := NormalizeServiceName(item.Service, item.Port)
		if service == "" {
			unsupported[i] = unsupportedScanResult(req, host, item)
			continue
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
	return out, unsupported, nil
}

func scanHost(target, resolvedIP string) string {
	if strings.TrimSpace(resolvedIP) != "" {
		return resolvedIP
	}
	return target
}

func mergeScanResults(req ScanRequest, supported []SecurityResult, unsupported map[int]SecurityResult) []SecurityResult {
	if len(req.Services) == 0 {
		return nil
	}

	results := make([]SecurityResult, len(req.Services))
	supportedIndex := 0
	for i := range req.Services {
		if item, ok := unsupported[i]; ok {
			results[i] = item
			continue
		}
		if supportedIndex >= len(supported) {
			results[i] = unsupportedScanResult(req, scanHost(req.Target, req.ResolvedIP), req.Services[i])
			continue
		}
		results[i] = supported[supportedIndex]
		supportedIndex++
	}
	return results
}

func unsupportedScanResult(req ScanRequest, resolvedIP string, item ScanService) SecurityResult {
	return SecurityResult{
		Target:      req.Target,
		ResolvedIP:  resolvedIP,
		Port:        item.Port,
		Service:     strings.TrimSpace(item.Service),
		ProbeKind:   ProbeKindCredential,
		FindingType: FindingTypeCredentialValid,
		Error:       fmt.Sprintf("unsupported service %q on port %d", item.Service, item.Port),
	}
}

func stubScanRunner(fn func(context.Context, []SecurityCandidate, CredentialProbeOptions) RunResult) func() {
	previous := scanRun
	scanRun = fn
	return func() {
		scanRun = previous
	}
}
