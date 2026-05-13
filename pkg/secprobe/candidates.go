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
	allowedList := make([]string, 0, len(opts.Protocols))
	for _, protocol := range opts.Protocols {
		p := NormalizeServiceName(protocol, 0)
		if p != "" {
			allowed[p] = struct{}{}
			allowedList = append(allowedList, p)
		}
	}

	out := make([]SecurityCandidate, 0, len(res.Ports))
	seen := make(map[string]struct{}, len(res.Ports))
	appendCandidate := func(candidate SecurityCandidate) {
		key := candidate.Target + "\x00" + candidate.ResolvedIP + "\x00" + candidate.Service + "\x00" + string(rune(candidate.Port))
		if _, ok := seen[key]; ok {
			return
		}
		if !registrySupportsCandidate(registry, candidate) {
			return
		}
		seen[key] = struct{}{}
		out = append(out, candidate)
	}
	for _, p := range res.Ports {
		if !p.Open {
			continue
		}
		service := NormalizeServiceName(p.Service, p.Port)
		if service == "" {
			if len(allowedList) == 0 {
				continue
			}
			for _, explicit := range allowedList {
				appendCandidate(SecurityCandidate{
					Target:     res.Target,
					ResolvedIP: res.ResolvedIP,
					Port:       p.Port,
					Service:    explicit,
					Version:    p.Version,
					Banner:     p.Banner,
				})
			}
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
		appendCandidate(candidate)
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
		if registry.hasCapability(candidate, kind) {
			return true
		}
	}

	return false
}
