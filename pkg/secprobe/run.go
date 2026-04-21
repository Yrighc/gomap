package secprobe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	ftpprobe "github.com/yrighc/gomap/internal/secprobe/ftp"
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

func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(sshprobe.New())
	r.Register(ftpprobe.New())
	r.Register(mysqlprobe.New())
	r.Register(postgresqlprobe.New())
	r.Register(redisprobe.New())
	r.Register(telnetprobe.New())
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
	applyDefaults(&opts)

	if registry == nil {
		registry = DefaultRegistry()
	}

	result := RunResult{
		Meta: SecurityMeta{Candidates: len(candidates)},
	}
	if len(candidates) == 0 {
		return result
	}

	type indexedCandidate struct {
		index     int
		candidate SecurityCandidate
	}

	jobs := make(chan indexedCandidate)
	results := make([]SecurityResult, len(candidates))

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

	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go worker()
	}

enqueue:
	for i, candidate := range candidates {
		select {
		case <-ctx.Done():
			break enqueue
		case jobs <- indexedCandidate{index: i, candidate: candidate}:
		}
	}
	close(jobs)
	wg.Wait()

	result.Results = trimZeroResults(results)
	return result
}

func probeCandidate(ctx context.Context, registry *Registry, candidate SecurityCandidate, opts CredentialProbeOptions) (SecurityResult, probeStatus) {
	base := SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		FindingType: FindingTypeCredentialValid,
	}

	prober, ok := registry.Lookup(candidate)
	if !ok {
		base.Error = "unsupported protocol"
		return base, probeSkipped
	}

	creds, err := credentialsForCandidate(candidate.Service, opts)
	if err != nil {
		base.Error = err.Error()
		return base, probeFailedBeforeAttempt
	}

	probeCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	result := prober.Probe(probeCtx, candidate, opts, creds)
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
	if result.FindingType == "" {
		result.FindingType = base.FindingType
	}

	if result.Success {
		return result, probeAttemptSucceeded
	}
	return result, probeAttemptFailed
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

func trimZeroResults(results []SecurityResult) []SecurityResult {
	out := make([]SecurityResult, 0, len(results))
	for _, item := range results {
		if item.Target == "" && item.ResolvedIP == "" && item.Port == 0 && item.Service == "" && item.FindingType == "" && !item.Success && item.Username == "" && item.Password == "" && item.Evidence == "" && item.Error == "" {
			continue
		}
		out = append(out, item)
	}
	return out
}
