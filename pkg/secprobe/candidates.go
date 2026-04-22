package secprobe

import (
	"sort"
	"strings"

	"github.com/yrighc/gomap/pkg/assetprobe"
)

var supportedByPort = map[int]string{
	21:   "ftp",
	22:   "ssh",
	23:   "telnet",
	27017: "mongodb",
	3306: "mysql",
	5432: "postgresql",
	6379: "redis",
}

func NormalizeServiceName(service string, port int) string {
	service = strings.ToLower(strings.TrimSpace(service))
	service = strings.TrimSuffix(service, "?")
	if service == "redis/tls" {
		service = "redis"
	}
	service = strings.TrimSuffix(service, "/ssl")
	switch service {
	case "postgres", "pgsql":
		service = "postgresql"
	case "mongo":
		service = "mongodb"
	}
	switch service {
	case "ftp", "ssh", "mysql", "postgresql", "redis", "telnet", "mongodb":
		return service
	case "":
		return supportedByPort[port]
	default:
		if v, ok := supportedByPort[port]; ok && strings.Contains(service, v) {
			return v
		}
		return supportedByPort[port]
	}
}

func BuildCandidates(res *assetprobe.ScanResult, opts CredentialProbeOptions) []SecurityCandidate {
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
		out = append(out, SecurityCandidate{
			Target:     res.Target,
			ResolvedIP: res.ResolvedIP,
			Port:       p.Port,
			Service:    service,
			Version:    p.Version,
			Banner:     p.Banner,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Target == out[j].Target {
			return out[i].Port < out[j].Port
		}
		return out[i].Target < out[j].Target
	})

	return out
}
