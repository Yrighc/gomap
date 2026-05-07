package metadata

import (
	"fmt"
	"path/filepath"
	"strings"

	appassets "github.com/yrighc/gomap/app"
	"gopkg.in/yaml.v3"
)

func LoadBuiltin() (map[string]Spec, error) {
	files, err := appassets.SecprobeProtocolFiles()
	if err != nil {
		return nil, err
	}

	specs := make(map[string]Spec, len(files))
	for _, file := range files {
		raw, err := appassets.SecprobeProtocol(filepath.Base(file))
		if err != nil {
			return nil, err
		}

		var spec Spec
		if err := yaml.Unmarshal(raw, &spec); err != nil {
			return nil, fmt.Errorf("parse %s: %w", file, err)
		}

		spec = normalizeSpec(spec)
		specs[spec.Name] = spec
	}
	return specs, nil
}

func normalizeSpec(spec Spec) Spec {
	spec.Name = strings.ToLower(strings.TrimSpace(spec.Name))
	spec.Aliases = normalizeStrings(spec.Aliases)
	spec.Dictionary.DefaultSources = normalizeStrings(spec.Dictionary.DefaultSources)
	spec.Dictionary.DefaultTiers = normalizeStrings(spec.Dictionary.DefaultTiers)
	spec.Templates.Unauthorized = strings.ToLower(strings.TrimSpace(spec.Templates.Unauthorized))
	return spec
}

func normalizeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
