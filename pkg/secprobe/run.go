package secprobe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
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
	credentialProber, hasCredential := registry.lookupCore(candidate, ProbeKindCredential)
	unauthorizedProber, hasUnauthorized := registry.lookupCore(candidate, ProbeKindUnauthorized)

	if !hasCredential && hasUnauthorized && !opts.EnableUnauthorized {
		result := markMatched(defaultResultForCandidateKind(candidate, ProbeKindUnauthorized))
		return markSkipped(result, core.SkipReasonProbeDisabled, "unsupported protocol"), probeSkipped
	}

	active := make([]struct {
		kind   ProbeKind
		prober core.Prober
	}, 0, 2)
	if hasCredential {
		active = append(active, struct {
			kind   ProbeKind
			prober core.Prober
		}{kind: ProbeKindCredential, prober: credentialProber})
	}
	if opts.EnableUnauthorized && hasUnauthorized {
		active = append(active, struct {
			kind   ProbeKind
			prober core.Prober
		}{kind: ProbeKindUnauthorized, prober: unauthorizedProber})
	}

	if len(active) == 0 {
		result := defaultResultForCandidate(registry, candidate, opts)
		return markSkipped(result, core.SkipReasonUnsupportedProtocol, "unsupported protocol"), probeSkipped
	}

	base := defaultResultForCandidate(registry, candidate, opts)
	attempted := false
	for _, item := range active {
		current := markMatched(defaultResultForCandidateKind(candidate, item.kind))

		var (
			creds []Credential
			err   error
		)
		if item.kind == ProbeKindCredential {
			creds, err = credentialsForCandidate(candidate.Service, opts)
			if err != nil {
				base = markSkipped(current, core.SkipReasonNoCredentials, err.Error())
				continue
			}
		}

		probeCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
		result := normalizeResult(current, item.prober.Probe(probeCtx, candidate, opts, creds), item.kind)
		cancel()
		attempted = true
		if result.Success {
			return markConfirmed(result), probeAttemptSucceeded
		}
		base = markAttemptFailure(result)
	}

	if attempted {
		return base, probeAttemptFailed
	}
	if base.SkipReason == core.SkipReasonNoCredentials {
		return markFailedBeforeAttempt(base), probeFailedBeforeAttempt
	}
	if base.SkipReason != "" {
		return base, probeSkipped
	}
	if base.Error != "" {
		return markFailedBeforeAttempt(base), probeFailedBeforeAttempt
	}

	return markSkipped(base, core.SkipReasonUnsupportedProtocol, "unsupported protocol"), probeSkipped
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
	return markFailedBeforeAttempt(result)
}

func defaultResultForCandidate(registry *Registry, candidate SecurityCandidate, opts CredentialProbeOptions) core.SecurityResult {
	kind := defaultProbeKindForCandidate(registry, candidate, opts)
	return defaultResultForCandidateKind(candidate, kind)
}

func defaultResultForCandidateKind(candidate SecurityCandidate, kind ProbeKind) core.SecurityResult {
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
		enriched := runEnrichment(ctx, item, opts)
		out[i] = markEnriched(item, enriched)
	}
	return out
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

func markMatched(result core.SecurityResult) core.SecurityResult {
	result.Stage = core.StageMatched
	result.SkipReason = ""
	return result
}

func markSkipped(result core.SecurityResult, reason core.SkipReason, message string) core.SecurityResult {
	result.SkipReason = reason
	if message != "" {
		result.Error = message
	}
	return result
}

func markAttemptFailure(result core.SecurityResult) core.SecurityResult {
	result.Stage = core.StageAttempted
	result.SkipReason = ""
	if result.FailureReason == "" {
		result.FailureReason = inferFailureReason(result.Error)
	}
	return result
}

func markFailedBeforeAttempt(result core.SecurityResult) core.SecurityResult {
	if result.FailureReason == "" {
		result.FailureReason = inferFailureReason(result.Error)
	}
	return result
}

func markConfirmed(result core.SecurityResult) core.SecurityResult {
	result.Stage = core.StageConfirmed
	result.SkipReason = ""
	return result
}

func markEnriched(before core.SecurityResult, after core.SecurityResult) core.SecurityResult {
	if after.Success && enrichmentAdded(before.Enrichment, after.Enrichment) {
		after.Stage = core.StageEnriched
		return after
	}
	after.Stage = before.Stage
	return after
}

func enrichmentAdded(before map[string]any, after map[string]any) bool {
	return len(after) > 0 && !reflect.DeepEqual(before, after)
}

func inferFailureReason(message string) core.FailureReason {
	text := strings.ToLower(message)
	switch {
	case text == "":
		return core.FailureReasonInsufficientConfirmation
	case strings.Contains(text, "context canceled"):
		return core.FailureReasonCanceled
	case strings.Contains(text, "deadline exceeded"), strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return core.FailureReasonTimeout
	case strings.Contains(text, "auth"), strings.Contains(text, "password"), strings.Contains(text, "login"), strings.Contains(text, "access denied"), strings.Contains(text, "permission denied"):
		return core.FailureReasonAuthentication
	case strings.Contains(text, "dial"), strings.Contains(text, "connect"), strings.Contains(text, "connection"), strings.Contains(text, "refused"), strings.Contains(text, "reset by peer"), strings.Contains(text, "no route"):
		return core.FailureReasonConnection
	default:
		return core.FailureReasonInsufficientConfirmation
	}
}
