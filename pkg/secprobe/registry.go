package secprobe

import (
	"context"
	"strings"

	"github.com/yrighc/gomap/internal/secprobe/core"
	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
)

type Prober interface {
	Name() string
	Kind() ProbeKind
	Match(candidate SecurityCandidate) bool
	Probe(ctx context.Context, candidate SecurityCandidate, opts CredentialProbeOptions, creds []Credential) SecurityResult
}

type Registry struct {
	core                *core.Registry
	atomicCredentials   map[string]registrybridge.CredentialAuthenticator
	atomicUnauthorizeds map[string]registrybridge.UnauthorizedChecker
}

func NewRegistry() *Registry {
	return &Registry{core: core.NewRegistry()}
}

func (r *Registry) Register(prober Prober) {
	if r == nil || prober == nil {
		return
	}
	r.ensureCore()
	r.core.Register(&registryProber{
		public: prober,
		core:   publicCoreProber{prober: prober},
	})
}

func (r *Registry) Lookup(candidate SecurityCandidate, kinds ...ProbeKind) (Prober, bool) {
	coreProber, ok := r.lookupCore(candidate, kinds...)
	if !ok {
		return nil, false
	}
	if wrapped, ok := coreProber.(*registryProber); ok {
		return wrapped.public, true
	}
	return corePublicProber{prober: coreProber}, true
}

func (r *Registry) registerCoreProber(prober core.Prober) {
	if r == nil || prober == nil {
		return
	}
	r.ensureCore()
	r.core.Register(&registryProber{
		public: corePublicProber{prober: prober},
		core:   prober,
	})
}

func (r *Registry) lookupCore(candidate SecurityCandidate, kinds ...ProbeKind) (core.Prober, bool) {
	if r == nil {
		return nil, false
	}
	r.ensureCore()
	return r.core.Lookup(candidate, kinds...)
}

func (r *Registry) RegisterAtomicCredential(protocol string, auth registrybridge.CredentialAuthenticator) {
	if r == nil || auth == nil {
		return
	}
	r.ensureAtomic()
	if name := canonicalRegistryProtocol(protocol); name != "" {
		r.atomicCredentials[name] = auth
	}
}

func (r *Registry) RegisterAtomicUnauthorized(protocol string, checker registrybridge.UnauthorizedChecker) {
	if r == nil || checker == nil {
		return
	}
	r.ensureAtomic()
	if name := canonicalRegistryProtocol(protocol); name != "" {
		r.atomicUnauthorizeds[name] = checker
	}
}

func (r *Registry) lookupAtomicCredential(candidate SecurityCandidate) (registrybridge.CredentialAuthenticator, bool) {
	if r == nil {
		return nil, false
	}
	r.ensureAtomic()
	auth, ok := r.atomicCredentials[canonicalCandidateProtocol(candidate)]
	return auth, ok
}

func (r *Registry) lookupAtomicUnauthorized(candidate SecurityCandidate) (registrybridge.UnauthorizedChecker, bool) {
	if r == nil {
		return nil, false
	}
	r.ensureAtomic()
	checker, ok := r.atomicUnauthorizeds[canonicalCandidateProtocol(candidate)]
	return checker, ok
}

func (r *Registry) ensureCore() {
	if r.core == nil {
		r.core = core.NewRegistry()
	}
}

func (r *Registry) ensureAtomic() {
	if r.atomicCredentials == nil {
		r.atomicCredentials = make(map[string]registrybridge.CredentialAuthenticator)
	}
	if r.atomicUnauthorizeds == nil {
		r.atomicUnauthorizeds = make(map[string]registrybridge.UnauthorizedChecker)
	}
}

func canonicalCandidateProtocol(candidate SecurityCandidate) string {
	if spec, ok := LookupProtocolSpec(candidate.Service, candidate.Port); ok {
		return canonicalProtocolToken(spec.Name)
	}
	if spec, ok := LookupProtocolSpec(candidate.Service, 0); ok && requiresStrictPortMatch(spec.Name) {
		return ""
	}
	return canonicalProtocolToken(candidate.Service)
}

func canonicalProtocolToken(protocol string) string {
	return strings.ToLower(strings.TrimSpace(protocol))
}

func canonicalRegistryProtocol(protocol string) string {
	if spec, ok := LookupProtocolSpec(protocol, 0); ok {
		return canonicalProtocolToken(spec.Name)
	}
	return canonicalProtocolToken(protocol)
}

func (r *Registry) hasCapability(candidate SecurityCandidate, kind ProbeKind) bool {
	switch kind {
	case ProbeKindCredential:
		if _, ok := r.lookupAtomicCredential(candidate); ok {
			return true
		}
	case ProbeKindUnauthorized:
		if _, ok := r.lookupAtomicUnauthorized(candidate); ok {
			return true
		}
	}
	_, ok := r.lookupCore(candidate, kind)
	return ok
}

type registryProber struct {
	public Prober
	core   core.Prober
}

func (p *registryProber) Name() string {
	return p.core.Name()
}

func (p *registryProber) Kind() core.ProbeKind {
	return p.core.Kind()
}

func (p *registryProber) Match(candidate core.SecurityCandidate) bool {
	return p.core.Match(candidate)
}

func (p *registryProber) Probe(ctx context.Context, candidate core.SecurityCandidate, opts core.CredentialProbeOptions, creds []core.Credential) core.SecurityResult {
	return p.core.Probe(ctx, candidate, opts, creds)
}

type publicCoreProber struct {
	prober Prober
}

func (p publicCoreProber) Name() string {
	return p.prober.Name()
}

func (p publicCoreProber) Kind() core.ProbeKind {
	return core.ProbeKind(p.prober.Kind())
}

func (p publicCoreProber) Match(candidate core.SecurityCandidate) bool {
	return p.prober.Match(SecurityCandidate(candidate))
}

func (p publicCoreProber) Probe(ctx context.Context, candidate core.SecurityCandidate, opts core.CredentialProbeOptions, creds []core.Credential) core.SecurityResult {
	return importSecurityResult(p.prober.Probe(
		ctx,
		SecurityCandidate(candidate),
		CredentialProbeOptions(opts),
		creds,
	))
}

type corePublicProber struct {
	prober core.Prober
}

func (p corePublicProber) Name() string {
	return p.prober.Name()
}

func (p corePublicProber) Kind() ProbeKind {
	return ProbeKind(p.prober.Kind())
}

func (p corePublicProber) Match(candidate SecurityCandidate) bool {
	return p.prober.Match(core.SecurityCandidate(candidate))
}

func (p corePublicProber) Probe(ctx context.Context, candidate SecurityCandidate, opts CredentialProbeOptions, creds []Credential) SecurityResult {
	return exportSecurityResult(p.prober.Probe(
		ctx,
		core.SecurityCandidate(candidate),
		core.CredentialProbeOptions(opts),
		creds,
	))
}
