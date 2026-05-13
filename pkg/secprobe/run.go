package secprobe

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	"github.com/yrighc/gomap/pkg/secprobe/credentials"
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
		opts.Timeout = time.Second
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

// probeCandidate 检查安全候选人的凭证和未授权访问情况
// 参数:
//   - ctx: 上下文信息，用于控制请求的超时和取消
//   - registry: 注册表，包含各种安全检查器
//   - candidate: 安全候选人，需要进行检查的目标
//   - opts: 凭证检查选项，包含超时等配置
//
// 返回值:
//   - core.SecurityResult: 安全检查结果
//   - probeStatus: 探查状态，表示检查是否成功、失败或跳过
func probeCandidate(ctx context.Context, registry *Registry, candidate SecurityCandidate, opts CredentialProbeOptions) (core.SecurityResult, probeStatus) {

	// 查找凭证检查器，并检查是否具有各种能力
	credentialProber, _ := registry.lookupCore(candidate, ProbeKindCredential)                        // 查找核心凭证检查器
	hasCredential := registry.hasCapability(candidate, ProbeKindCredential)                           // 是否具有凭证能力
	hasUnauthorized := registry.hasCapability(candidate, ProbeKindUnauthorized)                       // 是否具有未授权访问能力
	hasBuiltinCredential := registry.hasBuiltinProvider(candidate, ProbeKindCredential)               // 是否具有内置凭证提供者
	hasBuiltinUnauthorized := registry.hasBuiltinProvider(candidate, ProbeKindUnauthorized)           // 是否具有内置未授权访问提供者
	hasCompatibilityCredential := registry.hasCompatibilityProber(candidate, ProbeKindCredential)     // 是否具有兼容性凭证检查器
	hasCompatibilityUnauthorized := registry.hasCompatibilityProber(candidate, ProbeKindUnauthorized) // 是否具有兼容性未授权访问检查器

	// 如果没有凭证能力但有未授权访问能力，且未启用未授权访问，则跳过检查
	if !hasCredential && hasUnauthorized && !opts.EnableUnauthorized {
		result := markMatched(defaultResultForCandidateKind(candidate, ProbeKindUnauthorized))
		return markSkipped(result, core.SkipReasonProbeDisabled, "unsupported protocol"), probeSkipped
	}
	// 如果没有内置凭证和未授权访问能力，但有兼容性凭证检查器，并且使用兼容性公共检查器，则使用传统方式检查
	if !hasBuiltinCredential && !hasBuiltinUnauthorized && hasCompatibilityCredential && usesCompatibilityPublicProber(credentialProber) {
		unauthorizedProber, _ := registry.lookupCore(candidate, ProbeKindUnauthorized)
		return probeCandidateLegacy(ctx, registry, candidate, opts, credentialProber, hasCredential, unauthorizedProber, hasUnauthorized)
	}

	// 为候选人编译检查计划
	plan, ok := compilePlanForCandidate(candidate, opts, hasCredential, hasUnauthorized)
	if !ok {
		result := defaultResultForCandidate(registry, candidate, opts)
		return markSkipped(result, core.SkipReasonUnsupportedProtocol, "unsupported protocol"), probeSkipped
	}

	// 准备运行输入，包括认证器和未授权访问检查器
	runInput := engine.Input{
		Authenticator:       credentialExecutor(registry, candidate, opts.Timeout),
		UnauthorizedChecker: unauthorizedExecutor(registry, candidate, opts.Timeout),
	}
	// 如果没有内置未授权访问能力但有兼容性未授权访问检查器，则使用兼容性未授权访问执行器
	if !hasBuiltinUnauthorized && hasCompatibilityUnauthorized {
		if unauthorizedProber, ok := registry.lookupCore(candidate, ProbeKindUnauthorized); ok {
			runInput.UnauthorizedChecker = compatibilityUnauthorizedExecutor(unauthorizedProber, opts.Timeout)
		}
	}
	// 如果有凭证能力，则设置凭证加载器
	if hasCredential {
		runInput.CredentialLoader = func() ([]strategy.Credential, error) {
			creds, err := credentialsForCandidate(candidate.Service, opts)
			if err != nil {
				return nil, err
			}
			return strategyCredentials(creds), nil
		}
	}

	// 运行引擎执行检查计划
	engineOut := engine.Run(ctx, plan, runInput)
	// 处理凭证错误
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

	// 处理检查成功的情况
	if engineOut.Success {
		kind := probeKindForCapability(engineOut.Capability)
		return markConfirmed(engineAttemptResult(candidate, kind, engineOut.Attempt)), probeAttemptSucceeded
	}

	// 处理检查失败但已尝试的情况
	if engineOut.Attempted {
		kind := probeKindForCapability(engineOut.Capability)
		return markAttemptFailure(engineAttemptResult(candidate, kind, engineOut.Attempt)), probeAttemptFailed
	}

	// 默认情况：跳过检查，因为不支持协议
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
	rawToken := rawProtocolToken(protocol)
	normalizedToken := normalizeProtocolToken(protocol)
	spec, ok, err := lookupRuntimeMetadataSpec(rawToken, normalizedToken, 0)
	if err != nil {
		return nil, fmt.Errorf("load secprobe metadata: %w", err)
	}
	if !ok {
		if legacy, ok := lookupLegacyProtocolSpec(rawToken, normalizedToken, 0); ok {
			spec = metadataSpecFromProtocolSpec(legacy)
		} else {
			return legacyCredentialsForCandidate(protocol, opts)
		}
	}

	profile := credentials.ProfileFromMetadata(spec.Name, spec.Dictionary)
	profile = profile.WithScanProfile(string(credentials.ScanProfileDefault))

	generated, _, err := (credentials.Generator{}).Generate(credentials.GenerateInput{
		Profile: profile,
		Inline:  strategyCredentials(opts.Credentials),
	})
	if err != nil {
		return nil, translateCredentialGenerationError(protocol, err)
	}
	return coreCredentials(generated), nil
}

func legacyCredentialsForCandidate(protocol string, opts CredentialProbeOptions) ([]Credential, error) {
	if len(opts.Credentials) > 0 {
		return dedupeCredentials(opts.Credentials), nil
	}
	return CredentialsFor(protocol, opts)
}

func translateCredentialGenerationError(protocol string, err error) error {
	if !credentials.IsMissingSource(err) {
		return err
	}
	return fmt.Errorf("credential dictionary not found for protocol %s", protocol)
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

func usesCompatibilityPublicProber(prober core.Prober) bool {
	wrapped, ok := prober.(*registryProber)
	if !ok {
		return false
	}
	_, isCoreBacked := wrapped.public.(corePublicProber)
	return !isCoreBacked
}

func credentialExecutor(registry *Registry, candidate SecurityCandidate, timeout time.Duration) registrybridge.CredentialAuthenticator {
	if registry != nil {
		if auth, ok := registry.lookupAtomicCredential(candidate); ok {
			return timedCredentialAuthenticator{timeout: timeout, next: auth}
		}
	}
	if registry == nil {
		return nil
	}
	prober, ok := registry.lookupCore(candidate, ProbeKindCredential)
	if !ok {
		return nil
	}
	return compatibilityCredentialExecutor(prober, timeout)
}

func compatibilityCredentialExecutor(prober core.Prober, timeout time.Duration) registrybridge.CredentialAuthenticator {
	if prober == nil {
		return nil
	}
	return registrybridge.PublicCredentialAdapter{
		Prober:  prober,
		Timeout: timeout,
	}
}

func unauthorizedExecutor(registry *Registry, candidate SecurityCandidate, timeout time.Duration) registrybridge.UnauthorizedChecker {
	if registry != nil {
		if checker, ok := registry.lookupAtomicUnauthorized(candidate); ok {
			return timedUnauthorizedChecker{timeout: timeout, next: checker}
		}
	}
	return nil
}

func compatibilityUnauthorizedExecutor(prober core.Prober, timeout time.Duration) registrybridge.UnauthorizedChecker {
	if prober == nil {
		return nil
	}
	return registrybridge.PublicUnauthorizedAdapter{
		Prober:  prober,
		Timeout: timeout,
	}
}

type timedCredentialAuthenticator struct {
	timeout time.Duration
	next    registrybridge.CredentialAuthenticator
}

// AuthenticateOnce
// timedCredentialAuthenticator 是一个带超时功能的认证器结构体
// 它实现了认证逻辑，并可以在指定超时时间内完成认证
func (t timedCredentialAuthenticator) AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) registrybridge.Attempt {
	// 检查下一个认证器是否存在
	if t.next == nil {
		return registrybridge.Attempt{}
	}
	// 检查超时时间是否设置有效
	if t.timeout <= 0 {
		// 如果未设置超时时间或超时时间无效，直接调用下一个认证器的认证方法
		return t.next.AuthenticateOnce(ctx, target, cred)
	}
	// 创建带有超时时间的上下文
	attemptCtx, cancel := context.WithTimeout(ctx, t.timeout)
	// 确保在函数返回时取消上下文，避免资源泄漏
	defer cancel()
	// 使用带超时的上下文调用下一个认证器的认证方法
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

func coreCredentials(creds []strategy.Credential) []Credential {
	if len(creds) == 0 {
		return nil
	}
	out := make([]Credential, 0, len(creds))
	for _, cred := range creds {
		out = append(out, Credential{
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
		Credentials:        strategyCredentials(opts.Credentials),
	}), true
}

func runtimeMetadataSpecForCandidate(candidate SecurityCandidate, hasCredential, hasUnauthorized bool) (metadata.Spec, bool) {
	rawToken := rawProtocolToken(candidate.Service)
	normalizedToken := normalizeProtocolToken(candidate.Service)
	spec, ok, err := lookupRuntimeMetadataSpec(rawToken, normalizedToken, candidate.Port)
	if err != nil {
		panic(fmt.Errorf("load secprobe metadata: %w", err))
	}
	if ok {
		return spec, true
	}

	if legacy, ok := lookupLegacyProtocolSpec(rawToken, normalizedToken, candidate.Port); ok {
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

func lookupRuntimeMetadataSpec(rawToken, token string, port int) (metadata.Spec, bool, error) {
	specs, err := builtinMetadataSpecsOnceValue()
	if err != nil {
		return metadata.Spec{}, false, err
	}

	if rawToken != "" {
		for _, spec := range specs {
			if spec.Name == rawToken || containsString(spec.Aliases, rawToken) {
				if !tokenSupportsPort(rawToken, port) {
					return metadata.Spec{}, false, nil
				}
				if port != 0 && requiresStrictPortMatch(spec.Name) && !containsPort(spec.Ports, port) {
					return metadata.Spec{}, false, nil
				}
				return spec, true, nil
			}
		}
	}

	if token != "" {
		for _, spec := range specs {
			if spec.Name == token || containsString(spec.Aliases, token) {
				if rawToken != "" && !tokenSupportsPort(rawToken, port) {
					return metadata.Spec{}, false, nil
				}
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
			DefaultUsers:   append([]string(nil), spec.DefaultUsers...),
			PasswordSource: spec.PasswordSource,
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
