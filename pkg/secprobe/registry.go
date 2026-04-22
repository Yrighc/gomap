package secprobe

import (
	"context"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

type Prober interface {
	Name() string
	Kind() ProbeKind
	Match(candidate SecurityCandidate) bool
	Probe(ctx context.Context, candidate SecurityCandidate, opts CredentialProbeOptions, creds []Credential) SecurityResult
}

type Registry struct {
	core *core.Registry
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

func (r *Registry) ensureCore() {
	if r.core == nil {
		r.core = core.NewRegistry()
	}
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
