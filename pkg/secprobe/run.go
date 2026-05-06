package secprobe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	"github.com/yrighc/gomap/pkg/secprobe/engine"
	"github.com/yrighc/gomap/pkg/secprobe/metadata"
	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
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
	credentialProber, _ := registry.lookupCore(candidate, ProbeKindCredential)
	unauthorizedProber, _ := registry.lookupCore(candidate, ProbeKindUnauthorized)
	hasCredential := registry.hasCapability(candidate, ProbeKindCredential)
	hasUnauthorized := registry.hasCapability(candidate, ProbeKindUnauthorized)

	if !hasCredential && hasUnauthorized && !opts.EnableUnauthorized {
		result := markMatched(defaultResultForCandidateKind(candidate, ProbeKindUnauthorized))
		return markSkipped(result, core.SkipReasonProbeDisabled, "unsupported protocol"), probeSkipped
	}
	if usesLegacyPublicProber(credentialProber) {
		return probeCandidateLegacy(ctx, registry, candidate, opts, credentialProber, hasCredential, unauthorizedProber, hasUnauthorized)
	}

	plan, ok := compilePlanForCandidate(candidate, opts, hasCredential, hasUnauthorized)
	if !ok {
		result := defaultResultForCandidate(registry, candidate, opts)
		return markSkipped(result, core.SkipReasonUnsupportedProtocol, "unsupported protocol"), probeSkipped
	}

	runInput := engine.Input{
		Authenticator:       credentialExecutor(registry, candidate, credentialProber, opts.Timeout),
		UnauthorizedChecker: unauthorizedExecutor(registry, candidate, unauthorizedProber, opts.Timeout),
	}
	if hasCredential {
		runInput.CredentialLoader = func() ([]strategy.Credential, error) {
			creds, err := credentialsForCandidate(candidate.Service, opts)
			if err != nil {
				return nil, err
			}
			return strategyCredentials(creds), nil
		}
	}

	engineOut := engine.Run(ctx, plan, runInput)
	if engineOut.CredentialError != nil {
		base := markSkipped(
			markMatched(defaultResultForCandidateKind(candidate, ProbeKindCredential)),
			core.SkipReasonNoCredentials,
			engineOut.CredentialError.Error(),
		)
		if engineOut.Attempted {
			return base, probeAttemptFailed
		}
		return markFailedBeforeAttempt(base), probeFailedBeforeAttempt
	}

	if engineOut.Success {
		kind := probeKindForCapability(engineOut.Capability)
		return markConfirmed(engineAttemptResult(candidate, kind, engineOut.Attempt)), probeAttemptSucceeded
	}

	if engineOut.Attempted {
		kind := probeKindForCapability(engineOut.Capability)
		return markAttemptFailure(engineAttemptResult(candidate, kind, engineOut.Attempt)), probeAttemptFailed
	}

	result := defaultResultForCandidate(registry, candidate, opts)
	return markSkipped(result, core.SkipReasonUnsupportedProtocol, "unsupported protocol"), probeSkipped
}

func probeCandidateLegacy(
	ctx context.Context,
	registry *Registry,
	candidate SecurityCandidate,
	opts CredentialProbeOptions,
	credentialProber core.Prober,
	hasCredential bool,
	unauthorizedProber core.Prober,
	hasUnauthorized bool,
) (core.SecurityResult, probeStatus) {
	active := make([]struct {
		kind   ProbeKind
		prober core.Prober
	}, 0, 2)
	if opts.EnableUnauthorized && hasUnauthorized && unauthorizedProber != nil {
		active = append(active, struct {
			kind   ProbeKind
			prober core.Prober
		}{kind: ProbeKindUnauthorized, prober: unauthorizedProber})
	}
	if hasCredential && credentialProber != nil {
		active = append(active, struct {
			kind   ProbeKind
			prober core.Prober
		}{kind: ProbeKindCredential, prober: credentialProber})
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
	candidates := CredentialDictionaryCandidates(protocol, dictDir)

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
		if registry != nil && registry.hasCapability(candidate, kind) {
			return kind
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

func probeKindForCapability(capability strategy.Capability) ProbeKind {
	if capability == strategy.CapabilityUnauthorized {
		return ProbeKindUnauthorized
	}
	return ProbeKindCredential
}

func engineAttemptResult(candidate SecurityCandidate, kind ProbeKind, attempt registrybridge.Attempt) core.SecurityResult {
	base := markMatched(defaultResultForCandidateKind(candidate, kind))
	if attempt.Legacy.Target != "" || attempt.Legacy.ResolvedIP != "" || attempt.Legacy.Port != 0 || attempt.Legacy.Service != "" || attempt.Legacy.Success || attempt.Legacy.Error != "" || attempt.Legacy.FailureReason != "" {
		return normalizeResult(base, attempt.Legacy, kind)
	}

	out := base
	out.Success = attempt.Result.Success
	out.Username = attempt.Result.Username
	out.Password = attempt.Result.Password
	out.Evidence = attempt.Result.Evidence
	out.Error = attempt.Result.Error
	if attempt.Result.ErrorCode != "" {
		out.FailureReason = core.FailureReason(attempt.Result.ErrorCode)
	}
	if attempt.Result.FindingType != "" {
		out.FindingType = result.LegacyFindingType(attempt.Result.FindingType)
	}
	return out
}

func usesLegacyPublicProber(prober core.Prober) bool {
	wrapped, ok := prober.(*registryProber)
	if !ok {
		return false
	}
	_, isCoreBacked := wrapped.public.(corePublicProber)
	return !isCoreBacked
}

func credentialExecutor(registry *Registry, candidate SecurityCandidate, prober core.Prober, timeout time.Duration) registrybridge.CredentialAuthenticator {
	if registry != nil {
		if auth, ok := registry.lookupAtomicCredential(candidate); ok {
			return timedCredentialAuthenticator{timeout: timeout, next: auth}
		}
	}
	if prober == nil {
		return nil
	}
	return registrybridge.LegacyCredentialAdapter{
		Prober:  prober,
		Timeout: timeout,
	}
}

func unauthorizedExecutor(registry *Registry, candidate SecurityCandidate, prober core.Prober, timeout time.Duration) registrybridge.UnauthorizedChecker {
	if registry != nil {
		if checker, ok := registry.lookupAtomicUnauthorized(candidate); ok {
			return timedUnauthorizedChecker{timeout: timeout, next: checker}
		}
	}
	if prober == nil {
		return nil
	}
	return registrybridge.LegacyUnauthorizedAdapter{
		Prober:  prober,
		Timeout: timeout,
	}
}

type timedCredentialAuthenticator struct {
	timeout time.Duration
	next    registrybridge.CredentialAuthenticator
}

func (t timedCredentialAuthenticator) AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) registrybridge.Attempt {
	if t.next == nil {
		return registrybridge.Attempt{}
	}
	if t.timeout <= 0 {
		return t.next.AuthenticateOnce(ctx, target, cred)
	}
	attemptCtx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	return t.next.AuthenticateOnce(attemptCtx, target, cred)
}

type timedUnauthorizedChecker struct {
	timeout time.Duration
	next    registrybridge.UnauthorizedChecker
}

func (t timedUnauthorizedChecker) CheckUnauthorizedOnce(ctx context.Context, target strategy.Target) registrybridge.Attempt {
	if t.next == nil {
		return registrybridge.Attempt{}
	}
	if t.timeout <= 0 {
		return t.next.CheckUnauthorizedOnce(ctx, target)
	}
	attemptCtx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	return t.next.CheckUnauthorizedOnce(attemptCtx, target)
}

func strategyCredentials(creds []Credential) []strategy.Credential {
	if len(creds) == 0 {
		return nil
	}
	out := make([]strategy.Credential, 0, len(creds))
	for _, cred := range creds {
		out = append(out, strategy.Credential{
			Username: cred.Username,
			Password: cred.Password,
		})
	}
	return out
}

func compilePlanForCandidate(candidate SecurityCandidate, opts CredentialProbeOptions, hasCredential, hasUnauthorized bool) (strategy.Plan, bool) {
	spec, ok := runtimeMetadataSpecForCandidate(candidate, hasCredential, hasUnauthorized)
	if !ok {
		return strategy.Plan{}, false
	}

	return strategy.Compile(spec, strategy.CompileInput{
		Target:             candidate.Target,
		IP:                 candidate.ResolvedIP,
		Port:               candidate.Port,
		EnableUnauthorized: opts.EnableUnauthorized,
		EnableEnrichment:   opts.EnableEnrichment,
		StopOnSuccess:      opts.StopOnSuccess,
		Timeout:            opts.Timeout,
		DictDir:            opts.DictDir,
		Credentials:        strategyCredentials(opts.Credentials),
	}), true
}

func runtimeMetadataSpecForCandidate(candidate SecurityCandidate, hasCredential, hasUnauthorized bool) (metadata.Spec, bool) {
	spec, ok, err := lookupRuntimeMetadataSpec(normalizeProtocolToken(candidate.Service), candidate.Port)
	if err != nil {
		panic(fmt.Errorf("load secprobe metadata: %w", err))
	}
	if ok {
		return spec, true
	}

	if legacy, ok := lookupLegacyProtocolSpec(normalizeProtocolToken(candidate.Service), candidate.Port); ok {
		return metadataSpecFromProtocolSpec(legacy), true
	}

	if hasCredential || hasUnauthorized {
		return metadata.Spec{
			Name: candidate.Service,
			Ports: []int{
				candidate.Port,
			},
			Capabilities: metadata.Capabilities{
				Credential:   hasCredential,
				Unauthorized: hasUnauthorized,
			},
			Results: metadata.ResultProfile{
				CredentialSuccessType:   string(result.FindingTypeCredentialValid),
				UnauthorizedSuccessType: string(result.FindingTypeUnauthorizedAccess),
			},
		}, true
	}

	return metadata.Spec{}, false
}

func lookupRuntimeMetadataSpec(token string, port int) (metadata.Spec, bool, error) {
	specs, err := builtinMetadataSpecsOnceValue()
	if err != nil {
		return metadata.Spec{}, false, err
	}

	if token != "" {
		for _, spec := range specs {
			if spec.Name == token || containsString(spec.Aliases, token) {
				if port != 0 && requiresStrictPortMatch(spec.Name) && !containsPort(spec.Ports, port) {
					return metadata.Spec{}, false, nil
				}
				return spec, true, nil
			}
		}
	}

	if port != 0 {
		for _, spec := range specs {
			if containsPort(spec.Ports, port) {
				return spec, true, nil
			}
		}
	}

	return metadata.Spec{}, false, nil
}

func metadataSpecFromProtocolSpec(spec ProtocolSpec) metadata.Spec {
	return metadata.Spec{
		Name:    spec.Name,
		Aliases: append([]string(nil), spec.Aliases...),
		Ports:   append([]int(nil), spec.Ports...),
		Capabilities: metadata.Capabilities{
			Credential:   containsProbeKind(spec.ProbeKinds, ProbeKindCredential),
			Unauthorized: containsProbeKind(spec.ProbeKinds, ProbeKindUnauthorized),
			Enrichment:   spec.SupportsEnrichment,
		},
		Dictionary: metadata.Dictionary{
			DefaultSources: append([]string(nil), spec.DictNames...),
		},
		Results: metadata.ResultProfile{
			CredentialSuccessType:   string(result.FindingTypeCredentialValid),
			UnauthorizedSuccessType: string(result.FindingTypeUnauthorizedAccess),
		},
	}
}

func containsProbeKind(kinds []ProbeKind, target ProbeKind) bool {
	for _, kind := range kinds {
		if kind == target {
			return true
		}
	}
	return false
}

func probeKindsForCandidate(opts CredentialProbeOptions) []ProbeKind {
	if opts.EnableUnauthorized {
		return []ProbeKind{ProbeKindUnauthorized, ProbeKindCredential}
	}
	return []ProbeKind{ProbeKindCredential}
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
