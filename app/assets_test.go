package appassets

import (
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestEmbeddedAssetprobeResourcesLoad(t *testing.T) {
	tests := []struct {
		name   string
		load   func() ([]byte, error)
		prefix string
	}{
		{
			name:   "service probes",
			load:   ServiceProbes,
			prefix: "# Gomap service detection probe list",
		},
		{
			name:   "services",
			load:   Services,
			prefix: "# THIS FILE IS GENERATED AUTOMATICALLY FROM A MASTER",
		},
		{
			name: "simple dict",
			load: func() ([]byte, error) {
				return Dict("simple")
			},
			prefix: "/.env\n/.git/config\n/.ssh/id_rsa\n",
		},
		{
			name: "normal dict",
			load: func() ([]byte, error) {
				return Dict("normal")
			},
			prefix: "/Alibaba-Nacos\n/nacos/\n/api/nacos/\n",
		},
		{
			name: "diff dict",
			load: func() ([]byte, error) {
				return Dict("diff")
			},
			prefix: "/tofile.asp\n/upfile.asp\n/newfile.asp\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.load()
			if err != nil {
				t.Fatalf("load failed: %v", err)
			}
			if len(data) == 0 {
				t.Fatal("expected non-empty data")
			}
			if !strings.HasPrefix(string(data), tt.prefix) {
				t.Fatalf("expected data to have prefix %q", tt.prefix)
			}
		})
	}
}

func TestEmbeddedSecprobePasswordSourceResourcesLoad(t *testing.T) {
	data, err := SecprobePasswordSource("builtin:passwords/global")
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) < 70 {
		t.Fatalf("expected fscan-sized global password source, got %d entries", len(lines))
	}
	for _, want := range []string{
		"123456",
		"admin123",
		"{user}@123",
		"P@ssw0rd!",
		"1qaz@WSX",
		"Charge123",
		"redis",
		"elastic123",
	} {
		if !slices.Contains(lines, want) {
			t.Fatalf("expected global password source to contain %q", want)
		}
	}
}

func TestEmbeddedSecprobePasswordSourceRejectsUnsupportedSource(t *testing.T) {
	_, err := SecprobePasswordSource("builtin:passwords/missing")
	if err == nil {
		t.Fatal("expected unsupported source error")
	}
}

func TestSecprobeDictDirectoryOnlyContainsSharedPasswordPool(t *testing.T) {
	allowed := map[string]struct{}{
		filepath.Clean("secprobe/dicts/passwords/global.txt"): {},
	}

	err := filepath.WalkDir("secprobe/dicts", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if _, ok := allowed[filepath.Clean(path)]; !ok {
			t.Fatalf("unexpected legacy secprobe dictionary file: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk secprobe dicts: %v", err)
	}
}

func TestSecprobeUnauthorizedTemplateResourcesLoad(t *testing.T) {
	files, err := SecprobeUnauthorizedTemplateFiles()
	if err != nil {
		t.Fatalf("list unauthorized templates: %v", err)
	}
	if !slices.Contains(files, "secprobe/templates/unauthorized/memcached.yaml") {
		t.Fatalf("expected memcached unauthorized template, got %v", files)
	}

	data, err := SecprobeUnauthorizedTemplate("memcached.yaml")
	if err != nil {
		t.Fatalf("load memcached unauthorized template: %v", err)
	}
	if !strings.Contains(string(data), "stats\\r\\n") {
		t.Fatalf("expected memcached unauthorized template to contain stats request, got %q", string(data))
	}
}
