package secprobe

import (
	"sort"

	"github.com/yrighc/gomap/pkg/assetprobe"
)

func NormalizeServiceName(service string, port int) string {
	spec, ok := LookupProtocolSpec(service, port)
	if !ok {
		return ""
	}
	return spec.Name
}

func BuildCandidates(res *assetprobe.ScanResult, opts CredentialProbeOptions) []SecurityCandidate {
	return buildCandidatesWithRegistry(res, opts, DefaultRegistry())
}

func buildCandidatesWithRegistry(res *assetprobe.ScanResult, opts CredentialProbeOptions, registry *Registry) []SecurityCandidate {
	if res == nil {
		return nil
	}

	allowed := make(map[string]struct{}, len(opts.Protocols))
	for _, protocol := range opts.Protocols {
		p := NormalizeServiceName(protocol, 0)
		if p != "" {
			allowed[p] = struct{}{}
		}
	}

	out := make([]SecurityCandidate, 0, len(res.Ports))
	for _, p := range res.Ports {
		if !p.Open {
			continue
		}
		service := NormalizeServiceName(p.Service, p.Port)
		if service == "" {
			continue
		}
		if len(allowed) > 0 {
			if _, ok := allowed[service]; !ok {
				continue
			}
		}
		candidate := SecurityCandidate{
			Target:     res.Target,
			ResolvedIP: res.ResolvedIP,
			Port:       p.Port,
			Service:    service,
			Version:    p.Version,
			Banner:     p.Banner,
		}
		if !registrySupportsCandidate(registry, candidate) {
			continue
		}
		out = append(out, candidate)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Target == out[j].Target {
			return out[i].Port < out[j].Port
		}
		return out[i].Target < out[j].Target
	})

	return out
}

func registrySupportsCandidate(registry *Registry, candidate SecurityCandidate) bool {
	if registry == nil {
		return false
	}

	spec, ok := LookupProtocolSpec(candidate.Service, candidate.Port)
	if !ok || len(spec.ProbeKinds) == 0 {
		return false
	}

	for _, kind := range spec.ProbeKinds {
		if _, ok := registry.Lookup(candidate, kind); ok {
			return true
		}
	}

	return false
}
