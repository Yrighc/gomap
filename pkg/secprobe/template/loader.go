package template

import (
	"fmt"
	"path/filepath"
	"strings"

	appassets "github.com/yrighc/gomap/app"
	"gopkg.in/yaml.v3"
)

type UnauthorizedTemplate struct {
	Name      string   `yaml:"name"`
	Transport string   `yaml:"transport"`
	Request   string   `yaml:"request"`
	Matchers  Matchers `yaml:"matchers"`
	Success   Success  `yaml:"success"`
}

type Matchers struct {
	Contains []string `yaml:"contains"`
}

type Success struct {
	FindingType string `yaml:"finding_type"`
	Evidence    string `yaml:"evidence"`
}

func LoadBuiltinUnauthorized() (map[string]UnauthorizedTemplate, error) {
	files, err := appassets.SecprobeUnauthorizedTemplateFiles()
	if err != nil {
		return nil, err
	}

	out := make(map[string]UnauthorizedTemplate, len(files))
	for _, file := range files {
		raw, err := appassets.SecprobeUnauthorizedTemplate(filepath.Base(file))
		if err != nil {
			return nil, err
		}

		var tpl UnauthorizedTemplate
		if err := yaml.Unmarshal(raw, &tpl); err != nil {
			return nil, fmt.Errorf("parse %s: %w", file, err)
		}
		tpl = normalizeUnauthorizedTemplate(tpl)
		out[tpl.Name] = tpl
	}
	return out, nil
}

func normalizeUnauthorizedTemplate(tpl UnauthorizedTemplate) UnauthorizedTemplate {
	tpl.Name = strings.ToLower(strings.TrimSpace(tpl.Name))
	tpl.Transport = strings.ToLower(strings.TrimSpace(tpl.Transport))
	tpl.Matchers.Contains = normalizeMatcherContains(tpl.Matchers.Contains)
	return tpl
}

func normalizeMatcherContains(values []string) []string {
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
