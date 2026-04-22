package secprobe

import (
	"path/filepath"
	"strings"
)

func CredentialDictionaryCandidates(protocol, dictDir string) []string {
	normalized := NormalizeServiceName(protocol, 0)
	if normalized == "" {
		normalized = strings.ToLower(strings.TrimSpace(protocol))
	}

	names := []string{normalized}
	if spec, ok := LookupProtocolSpec(normalized, 0); ok && len(spec.DictNames) > 0 {
		names = spec.DictNames
	}

	out := make([]string, 0, len(names)*2)
	seen := make(map[string]struct{}, len(names)*2)
	for _, name := range names {
		for _, path := range []string{
			filepath.Join(dictDir, name+".txt"),
			filepath.Join(dictDir, "secprobe-"+name+".txt"),
		} {
			if _, ok := seen[path]; ok {
				continue
			}
			seen[path] = struct{}{}
			out = append(out, path)
		}
	}

	return out
}
