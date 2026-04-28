# App Resource Layout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reorganize `app/` assets by scan engine, unify embedded and external dictionary naming, and update code/tests/docs to use the new structure with no legacy compatibility layer.

**Architecture:** Keep `app/assets.go` as the single embedded-resource entrypoint, but retarget it to `app/assetprobe/...` and `app/secprobe/...` subdirectories. Make `pkg/secprobe/dictionaries.go` enforce one external naming convention, `<protocol>.txt`, while updating tests and docs so the repository only advertises the new layout.

**Tech Stack:** Go `embed`, Go testing package, existing `pkg/assetprobe` and `pkg/secprobe` helpers, Markdown docs, shell file move commands.

---

### Task 1: Lock the New Embedded Resource Layout with Tests

**Files:**
- Create: `app/assets_test.go`
- Modify: `pkg/secprobe/dictionaries_test.go`
- Test: `app/assets_test.go`
- Test: `pkg/secprobe/dictionaries_test.go`

- [ ] **Step 1: Write the failing embedded-layout and dictionary-candidate tests**

Create `app/assets_test.go` with:

```go
package appassets

import "testing"

func TestEmbeddedAssetprobeResourcesLoad(t *testing.T) {
	tests := []struct {
		name string
		load func() ([]byte, error)
	}{
		{name: "service probes", load: ServiceProbes},
		{name: "services", load: Services},
		{name: "simple dict", load: func() ([]byte, error) { return Dict("simple") }},
		{name: "normal dict", load: func() ([]byte, error) { return Dict("normal") }},
		{name: "diff dict", load: func() ([]byte, error) { return Dict("diff") }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.load()
			if err != nil {
				t.Fatalf("load %s: %v", tt.name, err)
			}
			if len(data) == 0 {
				t.Fatalf("expected %s data", tt.name)
			}
		})
	}
}

func TestEmbeddedSecprobeDictResourcesLoad(t *testing.T) {
	for _, protocol := range []string{"ftp", "mysql", "postgresql", "redis", "ssh", "telnet"} {
		t.Run(protocol, func(t *testing.T) {
			data, err := SecprobeDict(protocol)
			if err != nil {
				t.Fatalf("load %s dict: %v", protocol, err)
			}
			if len(data) == 0 {
				t.Fatalf("expected %s dict data", protocol)
			}
		})
	}
}
```

Update `pkg/secprobe/dictionaries_test.go` so the expected candidates only use `<protocol>.txt`:

```go
package secprobe

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestCredentialDictionaryCandidatesUsesCatalogDictNames(t *testing.T) {
	got := CredentialDictionaryCandidates("postgresql", "/tmp/dicts")
	want := []string{
		filepath.Join("/tmp/dicts", "postgresql.txt"),
		filepath.Join("/tmp/dicts", "postgres.txt"),
	}

	if len(got) != len(want) {
		t.Fatalf("expected %d candidates, got %d: %v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidate[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCredentialDictionaryCandidatesUsesCatalogDictNamesForAlias(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		want     []string
	}{
		{
			name:     "postgres alias",
			protocol: "postgres",
			want: []string{
				filepath.Join("/tmp/dicts", "postgresql.txt"),
				filepath.Join("/tmp/dicts", "postgres.txt"),
			},
		},
		{
			name:     "redis tls alias",
			protocol: "redis/tls",
			want: []string{
				filepath.Join("/tmp/dicts", "redis.txt"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CredentialDictionaryCandidates(tt.protocol, "/tmp/dicts"); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("CredentialDictionaryCandidates(%q) = %v, want %v", tt.protocol, got, tt.want)
			}
		})
	}
}

func TestCredentialDictionaryCandidatesFallsBackForUnknownProtocol(t *testing.T) {
	got := CredentialDictionaryCandidates("CustomSvc", "/tmp/dicts")
	want := []string{
		filepath.Join("/tmp/dicts", "CustomSvc.txt"),
	}

	if len(got) != len(want) {
		t.Fatalf("expected %d candidates, got %d: %v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidate[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCredentialDictionaryCandidatesSkipsEmptyProtocol(t *testing.T) {
	if got := CredentialDictionaryCandidates("", "/tmp/dicts"); len(got) != 0 {
		t.Fatalf("expected no candidates for empty protocol, got %v", got)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail against the old layout/rules**

Run: `go test ./app ./pkg/secprobe -run 'TestEmbeddedAssetprobeResourcesLoad|TestEmbeddedSecprobeDictResourcesLoad|TestCredentialDictionaryCandidates'`

Expected: FAIL because `app/assets.go` still reads flat paths and `pkg/secprobe/dictionaries.go` still returns `secprobe-*.txt` candidates.

- [ ] **Step 3: Write the minimal implementation for the new embedded resource paths**

Move the resource files into the new directory structure:

```bash
mkdir -p app/assetprobe/probes app/assetprobe/services app/assetprobe/dicts app/secprobe/dicts
mv app/gomap-service-probes app/assetprobe/probes/gomap-service-probes
mv app/gomap-services app/assetprobe/services/gomap-services
mv app/dict-simple.txt app/assetprobe/dicts/simple.txt
mv app/dict-normal.txt app/assetprobe/dicts/normal.txt
mv app/dict-diff.txt app/assetprobe/dicts/diff.txt
mv app/secprobe-ftp.txt app/secprobe/dicts/ftp.txt
mv app/secprobe-mysql.txt app/secprobe/dicts/mysql.txt
mv app/secprobe-postgresql.txt app/secprobe/dicts/postgresql.txt
mv app/secprobe-redis.txt app/secprobe/dicts/redis.txt
mv app/secprobe-ssh.txt app/secprobe/dicts/ssh.txt
mv app/secprobe-telnet.txt app/secprobe/dicts/telnet.txt
```

Update `app/assets.go` to:

```go
package appassets

import (
	"embed"
	"fmt"
)

//go:embed assetprobe/probes/gomap-service-probes assetprobe/services/gomap-services assetprobe/dicts/simple.txt assetprobe/dicts/normal.txt assetprobe/dicts/diff.txt secprobe/dicts/ftp.txt secprobe/dicts/mysql.txt secprobe/dicts/postgresql.txt secprobe/dicts/redis.txt secprobe/dicts/ssh.txt secprobe/dicts/telnet.txt
var files embed.FS

func ServiceProbes() ([]byte, error) {
	return files.ReadFile("assetprobe/probes/gomap-service-probes")
}

func Services() ([]byte, error) {
	return files.ReadFile("assetprobe/services/gomap-services")
}

func Dict(level string) ([]byte, error) {
	switch level {
	case "simple":
		return files.ReadFile("assetprobe/dicts/simple.txt")
	case "normal":
		return files.ReadFile("assetprobe/dicts/normal.txt")
	case "diff":
		return files.ReadFile("assetprobe/dicts/diff.txt")
	default:
		return nil, fmt.Errorf("unsupported dict level: %s", level)
	}
}

func SecprobeDict(protocol string) ([]byte, error) {
	switch protocol {
	case "ftp":
		return files.ReadFile("secprobe/dicts/ftp.txt")
	case "mysql":
		return files.ReadFile("secprobe/dicts/mysql.txt")
	case "postgresql":
		return files.ReadFile("secprobe/dicts/postgresql.txt")
	case "redis":
		return files.ReadFile("secprobe/dicts/redis.txt")
	case "ssh":
		return files.ReadFile("secprobe/dicts/ssh.txt")
	case "telnet":
		return files.ReadFile("secprobe/dicts/telnet.txt")
	default:
		return nil, fmt.Errorf("unsupported secprobe dict protocol: %s", protocol)
	}
}
```

- [ ] **Step 4: Run the tests to verify the embedded layout now passes**

Run: `go test ./app ./pkg/secprobe -run 'TestEmbeddedAssetprobeResourcesLoad|TestEmbeddedSecprobeDictResourcesLoad'`

Expected: PASS.

- [ ] **Step 5: Commit the embedded layout change**

```bash
git add app/assets.go app/assets_test.go app/assetprobe app/secprobe
git commit -m "refactor(app): reorganize embedded scan resources"
```

### Task 2: Enforce the New External `secprobe` Dictionary Naming Rule

**Files:**
- Modify: `pkg/secprobe/dictionaries.go`
- Modify: `pkg/secprobe/dictionaries_test.go`
- Test: `pkg/secprobe/dictionaries_test.go`

- [ ] **Step 1: Re-run the focused candidate tests and confirm the naming rule still fails**

Run: `go test ./pkg/secprobe -run 'TestCredentialDictionaryCandidates'`

Expected: FAIL because `CredentialDictionaryCandidates()` still appends both `<protocol>.txt` and `secprobe-<protocol>.txt`.

- [ ] **Step 2: Write the minimal implementation to remove legacy candidate generation**

Update `pkg/secprobe/dictionaries.go` to:

```go
package secprobe

import (
	"path/filepath"
	"strings"
)

func CredentialDictionaryCandidates(protocol, dictDir string) []string {
	normalized := NormalizeServiceName(protocol, 0)
	if normalized != "" {
		if spec, ok := LookupProtocolSpec(normalized, 0); ok && len(spec.DictNames) > 0 {
			return credentialDictionaryCandidatesForNames(spec.DictNames, dictDir)
		}
	}

	if strings.TrimSpace(protocol) == "" {
		return nil
	}

	return credentialDictionaryCandidatesForNames([]string{protocol}, dictDir)
}

func credentialDictionaryCandidatesForNames(names []string, dictDir string) []string {
	out := make([]string, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if strings.TrimSpace(name) == "" {
			continue
		}
		path := filepath.Join(dictDir, name+".txt")
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}

	return out
}
```

- [ ] **Step 3: Run the candidate tests to verify the new rule passes**

Run: `go test ./pkg/secprobe -run 'TestCredentialDictionaryCandidates'`

Expected: PASS.

- [ ] **Step 4: Run the broader secprobe asset tests to catch regressions**

Run: `go test ./pkg/secprobe -run 'TestBuiltinCredentialsLoadByProtocol|TestCredentialDictionaryCandidates'`

Expected: PASS.

- [ ] **Step 5: Commit the naming-rule change**

```bash
git add pkg/secprobe/dictionaries.go pkg/secprobe/dictionaries_test.go
git commit -m "refactor(secprobe): unify external dictionary naming"
```

### Task 3: Update Repository Docs to the New Resource Structure

**Files:**
- Modify: `README.md`
- Modify: `UPGRADE.md`
- Modify: `docs/secprobe-protocol-extension-guide.md`

- [ ] **Step 1: Capture the existing old-path references that must disappear**

Run:

```bash
rg -n "app/gomap-service-probes|app/gomap-services|app/dict-|app/secprobe-|secprobe-<name>|secprobe-\\*|secprobe-ssh.txt|secprobe-mysql.txt" README.md UPGRADE.md docs/secprobe-protocol-extension-guide.md
```

Expected: MATCHES showing the legacy layout and legacy `secprobe-*.txt` naming still documented.

- [ ] **Step 2: Update the docs to describe only the new layout**

Apply these content changes:

For `README.md`, replace the directory tree block with:

```text
├── app/
│   ├── assetprobe/
│   │   ├── probes/
│   │   │   └── gomap-service-probes  # 服务识别探针规则
│   │   ├── services/
│   │   │   └── gomap-services        # 端口服务映射
│   │   └── dicts/
│   │       ├── simple.txt            # 目录爆破字典（simple）
│   │       ├── normal.txt            # 目录爆破字典（normal）
│   │       └── diff.txt              # 目录爆破字典（diff）
│   └── secprobe/
│       └── dicts/
│           └── *.txt                 # 内置协议口令字典
```

Also update the architecture text snippets to:

```text
- 结合 `app/assetprobe/probes/gomap-service-probes` 规则进行协议探测与匹配
- 结合 `app/assetprobe/services/gomap-services` 做端口服务兜底映射
```

and:

```text
         | app/assetprobe/probes/gomap-service-probes |
         | app/assetprobe/services/gomap-services     |
         | app/assetprobe/dicts/*.txt                 |
         | app/secprobe/dicts/*.txt                   |
```

For `UPGRADE.md`, replace the old flat asset list with:

```text
- `app/assetprobe/probes/gomap-service-probes`
- `app/assetprobe/services/gomap-services`
- `app/assetprobe/dicts/simple.txt`
- `app/assetprobe/dicts/normal.txt`
- `app/assetprobe/dicts/diff.txt`
```

and update the sample error path to:

```text
load probes failed: open /home/runner/go/pkg/mod/github.com/yrighc/gomap@.../app/assetprobe/probes/gomap-service-probes: no such file or directory
```

For `docs/secprobe-protocol-extension-guide.md`, change the naming rule section to:

```text
- 当前候选文件名规则是 `<name>.txt`。
- 对 `Run()` / 默认 CLI 路径来说，仅补 `DictNames` 还不够；若协议支持内置 credential 字典，还需要同步补齐 `app/assets.go` 中的 embed 资源和 `SecprobeDict` 分支，否则默认内置字典不可用。
```

and update the checklist to:

```text
- `app` 内嵌资源已包含对应 `app/secprobe/dicts/<protocol>.txt`
```

- [ ] **Step 3: Verify the doc sweep removed the old layout references**

Run:

```bash
rg -n "app/gomap-service-probes|app/gomap-services|app/dict-|app/secprobe-|secprobe-<name>|secprobe-ssh.txt|secprobe-mysql.txt" README.md UPGRADE.md docs/secprobe-protocol-extension-guide.md
```

Expected: no matches.

- [ ] **Step 4: Commit the doc update**

```bash
git add README.md UPGRADE.md docs/secprobe-protocol-extension-guide.md
git commit -m "docs(app): document the new resource layout"
```

### Task 4: Run Final Verification for the Full Layout Cutover

**Files:**
- Modify: `app/assets.go`
- Modify: `app/assets_test.go`
- Modify: `pkg/secprobe/dictionaries.go`
- Modify: `pkg/secprobe/dictionaries_test.go`
- Modify: `README.md`
- Modify: `UPGRADE.md`
- Modify: `docs/secprobe-protocol-extension-guide.md`

- [ ] **Step 1: Run the focused package verification suite**

Run: `go test ./app ./pkg/secprobe ./pkg/assetprobe ./cmd`

Expected: PASS.

- [ ] **Step 2: Verify there are no legacy flat resource filenames left under `app/`**

Run:

```bash
find app -maxdepth 2 -type f | sort
```

Expected output contains:

```text
app/application.yml
app/assets.go
app/assets_test.go
app/assetprobe/dicts/diff.txt
app/assetprobe/dicts/normal.txt
app/assetprobe/dicts/simple.txt
app/assetprobe/probes/gomap-service-probes
app/assetprobe/services/gomap-services
app/gomap-kafka-dev.yml
app/gomap-kafka-prod.yml
app/secprobe/dicts/ftp.txt
app/secprobe/dicts/mysql.txt
app/secprobe/dicts/postgresql.txt
app/secprobe/dicts/redis.txt
app/secprobe/dicts/ssh.txt
app/secprobe/dicts/telnet.txt
```

and does not contain any of:

```text
app/dict-simple.txt
app/dict-normal.txt
app/dict-diff.txt
app/secprobe-ftp.txt
app/secprobe-ssh.txt
```

- [ ] **Step 3: Verify the worktree only contains the intended resource-layout changes**

Run: `git status --short`

Expected: only the files from this plan are modified or newly tracked.

- [ ] **Step 4: Commit the final verification checkpoint**

```bash
git add app pkg README.md UPGRADE.md docs/secprobe-protocol-extension-guide.md
git commit -m "test: verify app resource layout cutover"
```
