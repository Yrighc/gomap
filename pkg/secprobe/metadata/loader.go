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
	spec.Dictionary.DefaultUsers = normalizeDefaultUsers(spec.Dictionary.DefaultUsers)
	spec.Dictionary.PasswordSource = strings.ToLower(strings.TrimSpace(spec.Dictionary.PasswordSource))
	spec.Dictionary.ExtraPasswords = normalizePasswords(spec.Dictionary.ExtraPasswords)
	spec.Dictionary.DefaultPairs = normalizeCredentialPairs(spec.Dictionary.DefaultPairs)
	spec.Dictionary.DefaultTiers = normalizeStrings(spec.Dictionary.DefaultTiers)
	spec.Templates.Unauthorized = strings.ToLower(strings.TrimSpace(spec.Templates.Unauthorized))
	return spec
}

func normalizeDefaultUsers(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, strings.ToLower(strings.TrimSpace(value)))
	}
	return out
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

func normalizePasswords(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
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

func normalizeCredentialPairs(pairs []CredentialPair) []CredentialPair {
	if len(pairs) == 0 {
		return nil
	}

	out := make([]CredentialPair, 0, len(pairs))
	for _, pair := range pairs {
		pair.Username = strings.TrimSpace(pair.Username)
		pair.Password = strings.TrimSpace(pair.Password)
		if pair.Username == "" || pair.Password == "" {
			continue
		}
		out = append(out, pair)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
