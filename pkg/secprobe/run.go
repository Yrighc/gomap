package secprobe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	ftpprobe "github.com/yrighc/gomap/internal/secprobe/ftp"
	mongodbprobe "github.com/yrighc/gomap/internal/secprobe/mongodb"
	mysqlprobe "github.com/yrighc/gomap/internal/secprobe/mysql"
	postgresqlprobe "github.com/yrighc/gomap/internal/secprobe/postgresql"
	redisprobe "github.com/yrighc/gomap/internal/secprobe/redis"
	sshprobe "github.com/yrighc/gomap/internal/secprobe/ssh"
	telnetprobe "github.com/yrighc/gomap/internal/secprobe/telnet"
)

type probeStatus uint8

const (
	probeSkipped probeStatus = iota
	probeFailedBeforeAttempt
	probeAttemptFailed
	probeAttemptSucceeded
)

var runEnrichment = func(ctx context.Context, result core.SecurityResult, opts CredentialProbeOptions) core.SecurityResult {
	return enrichResult(ctx, result, opts)
}

func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.registerCoreProber(sshprobe.New())
	r.registerCoreProber(ftpprobe.New())
	r.registerCoreProber(mysqlprobe.New())
	r.registerCoreProber(postgresqlprobe.New())
	r.registerCoreProber(redisprobe.New())
	r.registerCoreProber(redisprobe.NewUnauthorized())
	r.registerCoreProber(telnetprobe.New())
	r.registerCoreProber(mongodbprobe.NewUnauthorized())
	return r
}

func applyDefaults(opts *CredentialProbeOptions) {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 10
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
}

func Run(ctx context.Context, candidates []SecurityCandidate, opts CredentialProbeOptions) RunResult {
	return RunWithRegistry(ctx, DefaultRegistry(), candidates, opts)
}

func RunWithRegistry(ctx context.Context, registry *Registry, candidates []SecurityCandidate, opts CredentialProbeOptions) RunResult {
	return exportRunResult(runWithRegistryInternal(ctx, registry, candidates, opts))
}

func runWithRegistryInternal(ctx context.Context, registry *Registry, candidates []SecurityCandidate, opts CredentialProbeOptions) core.RunResult {
	applyDefaults(&opts)

	if registry == nil {
		registry = DefaultRegistry()
	}

	result := core.RunResult{
		Meta: core.SecurityMeta{Candidates: len(candidates)},
	}
	if len(candidates) == 0 {
		return result
	}
	if err := ctx.Err(); err != nil {
		results := make([]core.SecurityResult, len(candidates))
		for i, candidate := range candidates {
			results[i] = canceledResult(registry, candidate, opts, err)
		}
		result.Meta.Failed = len(candidates)
		result.Results = results
		return result
	}

	type indexedCandidate struct {
		index     int
		candidate SecurityCandidate
	}

	jobs := make(chan indexedCandidate, len(candidates))
	results := make([]core.SecurityResult, len(candidates))

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)

	worker := func() {
		defer wg.Done()

		for job := range jobs {
			item, status := probeCandidate(ctx, registry, job.candidate, opts)

			mu.Lock()
			results[job.index] = item

			switch status {
			case probeSkipped:
				result.Meta.Skipped++
			case probeFailedBeforeAttempt:
				result.Meta.Failed++
			case probeAttemptSucceeded:
				result.Meta.Attempted++
				result.Meta.Succeeded++
			case probeAttemptFailed:
				result.Meta.Attempted++
				result.Meta.Failed++
			}
			mu.Unlock()
		}
	}

	for i, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			for j := i; j < len(candidates); j++ {
				results[j] = canceledResult(registry, candidates[j], opts, err)
				result.Meta.Failed++
			}
			break
		}
		jobs <- indexedCandidate{index: i, candidate: candidate}
	}
	close(jobs)

	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go worker()
	}
	wg.Wait()

	result.Results = applyEnrichment(ctx, results, opts)
	return result
}

func probeCandidate(ctx context.Context, registry *Registry, candidate SecurityCandidate, opts CredentialProbeOptions) (core.SecurityResult, probeStatus) {
	base := defaultResultForCandidate(registry, candidate, opts)

	attempted := false
	for _, kind := range probeKindsForCandidate(opts) {
		prober, ok := registry.lookupCore(candidate, kind)
		if !ok {
			continue
		}

		var (
			creds []Credential
			err   error
		)
		if kind == ProbeKindCredential {
			creds, err = credentialsForCandidate(candidate.Service, opts)
			if err != nil {
				base.ProbeKind = kind
				base.FindingType = defaultFindingTypeForKind(kind)
				base.Error = err.Error()
				continue
			}
		}

		probeCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
		result := normalizeResult(base, prober.Probe(probeCtx, candidate, opts, creds), kind)
		cancel()
		attempted = true
		if result.Success {
			return result, probeAttemptSucceeded
		}
		base = result
	}

	if attempted {
		return base, probeAttemptFailed
	}
	if base.Error != "" {
		return base, probeFailedBeforeAttempt
	}

	base.Error = "unsupported protocol"
	return base, probeSkipped
}

func credentialsForCandidate(protocol string, opts CredentialProbeOptions) ([]Credential, error) {
	if len(opts.Credentials) > 0 {
		return dedupeCredentials(opts.Credentials), nil
	}
	if opts.DictDir != "" {
		return loadCredentialsFromDir(protocol, opts.DictDir)
	}
	return CredentialsFor(protocol, opts)
}

func loadCredentialsFromDir(protocol, dictDir string) ([]Credential, error) {
	candidates := []string{
		filepath.Join(dictDir, protocol+".txt"),
		filepath.Join(dictDir, "secprobe-"+protocol+".txt"),
	}

	var lastErr error
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				lastErr = err
				continue
			}
			return nil, err
		}

		creds, err := parseCredentialLines(string(data))
		if err != nil {
			return nil, fmt.Errorf("parse %s credentials: %w", protocol, err)
		}
		return dedupeCredentials(creds), nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("credential dictionary not found for protocol %s in %s", protocol, dictDir)
	}
	return nil, fmt.Errorf("credential dictionary not found for protocol %s", protocol)
}

func canceledResult(registry *Registry, candidate SecurityCandidate, opts CredentialProbeOptions, err error) core.SecurityResult {
	result := defaultResultForCandidate(registry, candidate, opts)
	if err != nil {
		result.Error = err.Error()
	}
	return result
}

func defaultResultForCandidate(registry *Registry, candidate SecurityCandidate, opts CredentialProbeOptions) core.SecurityResult {
	kind := defaultProbeKindForCandidate(registry, candidate, opts)
	return core.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		ProbeKind:   kind,
		FindingType: defaultFindingTypeForKind(kind),
	}
}

func normalizeResult(base core.SecurityResult, result core.SecurityResult, kind ProbeKind) core.SecurityResult {
	if result.Target == "" {
		result.Target = base.Target
	}
	if result.ResolvedIP == "" {
		result.ResolvedIP = base.ResolvedIP
	}
	if result.Port == 0 {
		result.Port = base.Port
	}
	if result.Service == "" {
		result.Service = base.Service
	}
	if result.ProbeKind == "" {
		result.ProbeKind = kind
	}
	if result.FindingType == "" {
		result.FindingType = defaultFindingTypeForKind(kind)
	}
	return result
}

func applyEnrichment(ctx context.Context, results []core.SecurityResult, opts CredentialProbeOptions) []core.SecurityResult {
	if !opts.EnableEnrichment || len(results) == 0 {
		return results
	}

	out := make([]core.SecurityResult, len(results))
	copy(out, results)
	for i, item := range out {
		if !item.Success {
			continue
		}
		out[i] = runEnrichment(ctx, item, opts)
	}
	return out
}

func enrichResult(ctx context.Context, result core.SecurityResult, opts CredentialProbeOptions) core.SecurityResult {
	switch result.Service {
	case "redis":
		return redisprobe.Enrich(ctx, result, opts)
	case "mongodb":
		return mongodbprobe.Enrich(ctx, result, opts)
	default:
		return result
	}
}

func defaultProbeKindForCandidate(registry *Registry, candidate SecurityCandidate, opts CredentialProbeOptions) ProbeKind {
	for _, kind := range probeKindsForCandidate(opts) {
		if registry != nil {
			if _, ok := registry.lookupCore(candidate, kind); ok {
				return kind
			}
		}
	}
	return ProbeKindCredential
}

func defaultFindingTypeForKind(kind ProbeKind) string {
	if kind == ProbeKindUnauthorized {
		return FindingTypeUnauthorizedAccess
	}
	return FindingTypeCredentialValid
}

func probeKindsForCandidate(opts CredentialProbeOptions) []ProbeKind {
	kinds := []ProbeKind{ProbeKindCredential}
	if opts.EnableUnauthorized {
		kinds = append(kinds, ProbeKindUnauthorized)
	}
	return kinds
}
