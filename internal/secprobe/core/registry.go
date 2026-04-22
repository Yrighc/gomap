package core

import "context"

type Prober interface {
	Name() string
	Kind() ProbeKind
	Match(candidate SecurityCandidate) bool
	Probe(ctx context.Context, candidate SecurityCandidate, opts CredentialProbeOptions, creds []Credential) SecurityResult
}

type Registry struct {
	probers []Prober
}

func NewRegistry() *Registry { return &Registry{} }

func (r *Registry) Register(prober Prober) { r.probers = append(r.probers, prober) }

func (r *Registry) Lookup(candidate SecurityCandidate, kinds ...ProbeKind) (Prober, bool) {
	kind := ProbeKindCredential
	if len(kinds) > 0 {
		kind = kinds[0]
	}
	for _, prober := range r.probers {
		if prober.Kind() != kind {
			continue
		}
		if prober.Match(candidate) {
			return prober, true
		}
	}
	return nil, false
}
