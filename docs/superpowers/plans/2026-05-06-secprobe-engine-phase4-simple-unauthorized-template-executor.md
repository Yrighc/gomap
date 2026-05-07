# secprobe Engine Phase 4 Simple Unauthorized Template Executor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a minimal, declarative unauthorized template executor for simple request/response protocols, and migrate `memcached` unauthorized detection onto that executor without turning YAML into a programmable DSL.

**Architecture:** Templates stay declarative and only describe static transport facts, a bounded request payload, expected response matchers, and success evidence. The executor owns network I/O, timeout handling, and failure-code mapping. This phase intentionally migrates `memcached` first because it fits a single TCP request/response model; `zookeeper` remains code-backed for now because it requires a real session client and is not a “simple template” target.

**Tech Stack:** Go, embedded app assets, `pkg/secprobe/metadata`, new `pkg/secprobe/template` package, `pkg/secprobe/registry`, `pkg/secprobe/result`, `app/assets.go`, and Go `testing`.

---

## Scope Decomposition

In scope:

- add a new embedded unauthorized-template asset directory
- add a loader and schema for simple unauthorized templates
- add a bounded TCP request/response executor
- migrate `memcached` unauthorized detection to the new template executor
- keep YAML declarative and explicitly non-programmable

Out of scope:

- `zookeeper` migration
- loops in template files
- state machines, retries, conditional branching, or arbitrary scripting in template YAML
- replacing code-backed unauthorized checks that require protocol libraries

---

## File Map

### Template schema and loading

- Create: `app/secprobe/templates/unauthorized/memcached.yaml`
- Modify: `app/assets.go`
- Modify: `pkg/secprobe/metadata/spec.go`
- Modify: `pkg/secprobe/metadata/loader.go`
- Modify: `pkg/secprobe/metadata/loader_test.go`

### Template executor

- Create: `pkg/secprobe/template/loader.go`
- Create: `pkg/secprobe/template/loader_test.go`
- Create: `pkg/secprobe/template/unauthorized.go`
- Create: `pkg/secprobe/template/unauthorized_test.go`

### Registry / runtime integration

- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`
- Modify: `pkg/secprobe/run_test.go`
- Modify: `pkg/secprobe/assets_test.go`
- Modify: `app/secprobe/protocols/memcached.yaml`
- Modify: `README.md`

---

## Task 1: Add a Declarative Template Reference to Metadata and Asset Loading

**Files:**
- Modify: `pkg/secprobe/metadata/spec.go`
- Modify: `pkg/secprobe/metadata/loader.go`
- Modify: `pkg/secprobe/metadata/loader_test.go`
- Modify: `app/assets.go`
- Create: `app/secprobe/templates/unauthorized/memcached.yaml`
- Modify: `app/secprobe/protocols/memcached.yaml`

- [ ] **Step 1: Add failing metadata tests for a simple unauthorized template reference**

Extend `pkg/secprobe/metadata/loader_test.go`:

```go
func TestLoadBuiltinKeepsUnauthorizedTemplateReferenceDeclarative(t *testing.T) {
	specs, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin() error = %v", err)
	}

	memcached := specs["memcached"]
	if memcached.Templates.Unauthorized != "memcached" {
		t.Fatalf("expected memcached unauthorized template reference, got %+v", memcached.Templates)
	}
}
```

- [ ] **Step 2: Extend the metadata schema with a template reference block**

Update `pkg/secprobe/metadata/spec.go`:

```go
type TemplateRefs struct {
	Unauthorized string `yaml:"unauthorized"`
}

type Spec struct {
	Name         string        `yaml:"name"`
	Aliases      []string      `yaml:"aliases"`
	Ports        []int         `yaml:"ports"`
	Capabilities Capabilities  `yaml:"capabilities"`
	PolicyTags   PolicyTags    `yaml:"policy_tags"`
	Dictionary   Dictionary    `yaml:"dictionary"`
	Results      ResultProfile `yaml:"results"`
	Templates    TemplateRefs  `yaml:"templates"`
}
```

Keep `normalizeSpec(...)` strict and shallow. Do not add execution semantics there beyond trimming and lowercasing the template name.

- [ ] **Step 3: Add the new embedded template asset and wire it into the app asset loader**

Update `app/assets.go`:

```go
//go:embed ... secprobe/protocols/*.yaml secprobe/templates/unauthorized/*.yaml
var files embed.FS

func SecprobeUnauthorizedTemplate(name string) ([]byte, error) {
	return files.ReadFile("secprobe/templates/unauthorized/" + name)
}

func SecprobeUnauthorizedTemplateFiles() ([]string, error) {
	return fs.Glob(files, "secprobe/templates/unauthorized/*.yaml")
}
```

Create `app/secprobe/templates/unauthorized/memcached.yaml`:

```yaml
name: memcached
transport: tcp
request: "stats\r\n"
matchers:
  contains:
    - "STAT version "
    - "\r\nEND\r\n"
success:
  finding_type: unauthorized_access
  evidence: stats returned version without authentication
```

Update `app/secprobe/protocols/memcached.yaml`:

```yaml
templates:
  unauthorized: memcached
```

- [ ] **Step 4: Run the metadata/asset baseline tests**

Run:

```bash
go test ./pkg/secprobe/metadata ./pkg/secprobe ./app -run 'TestLoadBuiltinKeepsUnauthorizedTemplateReferenceDeclarative|TestSecprobe' -v
```

Expected: FAIL because the template schema and asset helpers do not exist yet.

- [ ] **Step 5: Commit the metadata and asset groundwork**

```bash
git add pkg/secprobe/metadata/spec.go pkg/secprobe/metadata/loader.go pkg/secprobe/metadata/loader_test.go app/assets.go app/secprobe/protocols/memcached.yaml app/secprobe/templates/unauthorized/memcached.yaml
git commit -m "feat(secprobe): 为未授权模板执行器补齐声明式元数据入口"
```

---

## Task 2: Implement the Simple Unauthorized Template Loader

**Files:**
- Create: `pkg/secprobe/template/loader.go`
- Create: `pkg/secprobe/template/loader_test.go`

- [ ] **Step 1: Add failing loader tests for the template schema**

Create `pkg/secprobe/template/loader_test.go`:

```go
func TestLoadBuiltinUnauthorizedTemplates(t *testing.T) {
	templates, err := LoadBuiltinUnauthorized()
	if err != nil {
		t.Fatalf("LoadBuiltinUnauthorized() error = %v", err)
	}

	tpl, ok := templates["memcached"]
	if !ok {
		t.Fatalf("expected memcached template, got keys %v", maps.Keys(templates))
	}
	if tpl.Transport != "tcp" || tpl.Request != "stats\r\n" {
		t.Fatalf("unexpected template: %+v", tpl)
	}
}
```

- [ ] **Step 2: Implement the template schema and loader**

Create `pkg/secprobe/template/loader.go`:

```go
package template

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
```

Keep normalization narrow:

- trim and lowercase `Name` / `Transport`
- preserve request payload bytes as-is
- drop empty `contains` entries

- [ ] **Step 3: Run the template-loader tests**

Run:

```bash
go test ./pkg/secprobe/template -run 'TestLoadBuiltinUnauthorizedTemplates' -v
```

Expected: PASS with the memcached template loaded from embedded assets.

- [ ] **Step 4: Commit the loader**

```bash
git add pkg/secprobe/template/loader.go pkg/secprobe/template/loader_test.go
git commit -m "feat(secprobe): 增加简单未授权模板加载器"
```

---

## Task 3: Implement the Bounded TCP Unauthorized Template Executor

**Files:**
- Create: `pkg/secprobe/template/unauthorized.go`
- Create: `pkg/secprobe/template/unauthorized_test.go`

- [ ] **Step 1: Add failing executor tests that lock the “simple only” contract**

Create `pkg/secprobe/template/unauthorized_test.go`:

```go
func TestUnauthorizedTemplateCheckerMatchesMemcachedStatsResponse(t *testing.T) {
	checker := NewUnauthorizedChecker(UnauthorizedTemplate{
		Name:      "memcached",
		Transport: "tcp",
		Request:   "stats\r\n",
		Matchers: Matchers{Contains: []string{"STAT version ", "\r\nEND\r\n"}},
		Success: Success{
			FindingType: "unauthorized_access",
			Evidence:    "stats returned version without authentication",
		},
	}, func(context.Context, strategy.Target, string) (string, error) {
		return "STAT version 1.6.21\r\nEND\r\n", nil
	})

	out := checker.CheckUnauthorizedOnce(context.Background(), strategy.Target{
		Host: "demo", IP: "127.0.0.1", Port: 11211, Protocol: "memcached",
	})

	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}
	if out.Result.FindingType != result.FindingTypeUnauthorizedAccess {
		t.Fatalf("unexpected finding type: %+v", out.Result)
	}
}
```

Also add a rejection case:

```go
func TestUnauthorizedTemplateCheckerRejectsUnsupportedTransport(t *testing.T) {
	checker := NewUnauthorizedChecker(UnauthorizedTemplate{Name: "bad", Transport: "udp"}, nil)
	out := checker.CheckUnauthorizedOnce(context.Background(), strategy.Target{Protocol: "bad"})
	if out.Result.ErrorCode != result.ErrorCodeInsufficientConfirmation {
		t.Fatalf("expected insufficient confirmation, got %+v", out.Result)
	}
}
```

- [ ] **Step 2: Implement the TCP-only unauthorized checker**

Create `pkg/secprobe/template/unauthorized.go`:

```go
package template

type exchangeFunc func(context.Context, strategy.Target, string) (string, error)

type UnauthorizedChecker struct {
	tpl      UnauthorizedTemplate
	exchange exchangeFunc
}

func NewUnauthorizedChecker(tpl UnauthorizedTemplate, exchange exchangeFunc) UnauthorizedChecker {
	if exchange == nil {
		exchange = exchangeTCP
	}
	return UnauthorizedChecker{tpl: tpl, exchange: exchange}
}

func (c UnauthorizedChecker) CheckUnauthorizedOnce(ctx context.Context, target strategy.Target) registrybridge.Attempt {
	if c.tpl.Transport != "tcp" {
		return registrybridge.Attempt{Result: result.Attempt{
			Error:       "unsupported unauthorized template transport",
			ErrorCode:   result.ErrorCodeInsufficientConfirmation,
			FindingType: result.FindingTypeUnauthorizedAccess,
		}}
	}

	reply, err := c.exchange(ctx, target, c.tpl.Request)
	if err != nil {
		return registrybridge.Attempt{Result: result.Attempt{
			Error:       err.Error(),
			ErrorCode:   classifyTemplateNetworkFailure(err),
			FindingType: result.FindingTypeUnauthorizedAccess,
		}}
	}
	if !containsAll(reply, c.tpl.Matchers.Contains) {
		return registrybridge.Attempt{Result: result.Attempt{
			Error:       "unauthorized template match failed",
			ErrorCode:   result.ErrorCodeInsufficientConfirmation,
			FindingType: result.FindingTypeUnauthorizedAccess,
		}}
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success:     true,
		Evidence:    c.tpl.Success.Evidence,
		FindingType: result.FindingTypeUnauthorizedAccess,
	}}
}
```

Keep helper behavior minimal:

- only one request
- only one full reply buffer
- only `contains-all` matching
- no loops, branches, retries, or multi-step negotiation

- [ ] **Step 3: Run the executor tests**

Run:

```bash
go test ./pkg/secprobe/template -run 'TestUnauthorizedTemplateChecker' -v
```

Expected: PASS with both the success case and the unsupported-transport guard green.

- [ ] **Step 4: Commit the executor**

```bash
git add pkg/secprobe/template/unauthorized.go pkg/secprobe/template/unauthorized_test.go
git commit -m "feat(secprobe): 增加简单 tcp 未授权模板执行器"
```

---

## Task 4: Migrate `memcached` to the Template Executor and Document the Boundary

**Files:**
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`
- Modify: `pkg/secprobe/run_test.go`
- Modify: `pkg/secprobe/assets_test.go`
- Modify: `README.md`

- [ ] **Step 1: Add failing integration tests for default-registry memcached template wiring**

Extend `pkg/secprobe/default_registry_test.go`:

```go
func TestDefaultRegistryRegistersMemcachedUnauthorizedTemplateChecker(t *testing.T) {
	r := DefaultRegistry()
	if _, ok := r.lookupAtomicUnauthorized(SecurityCandidate{Service: "memcached", Port: 11211}); !ok {
		t.Fatal("expected memcached unauthorized template checker")
	}
}
```

And extend `pkg/secprobe/run_test.go` with a small integration harness that injects a template-backed unauthorized checker and expects `unauthorized_access`.

- [ ] **Step 2: Wire the memcached template into the default registry**

Update `pkg/secprobe/default_registry.go` to load the built-in template and register it:

```go
func RegisterDefaultProbers(r *Registry) {
	// existing atomic credential and redis unauthorized registration...

	if templates, err := template.LoadBuiltinUnauthorized(); err == nil {
		if tpl, ok := templates["memcached"]; ok {
			r.RegisterAtomicUnauthorized("memcached", template.NewUnauthorizedChecker(tpl, nil))
		}
	}

	r.registerCoreProber(zookeeperprobe.NewUnauthorized())
}
```

At this stage, remove the built-in `memcachedprobe.NewUnauthorized()` registration from `registerCoreProber(...)` so memcached’s unauthorized path is engine + template based.

- [ ] **Step 3: Lock asset coverage and document why `zookeeper` stays code-backed**

Update `pkg/secprobe/assets_test.go` with a small assertion that the embedded memcached template is discoverable, then document in `README.md`:

```md
### secprobe engine phase 4

- `memcached` unauthorized detection now uses a declarative simple-template executor
- Templates remain bounded to one transport, one request, and matcher-based confirmation
- `zookeeper` stays code-backed because it requires a real session client and is not a simple request/response protocol
```

- [ ] **Step 4: Run the focused unauthorized-template regression suite**

Run:

```bash
go test ./pkg/secprobe ./pkg/secprobe/template ./app -run 'TestDefaultRegistryRegistersMemcachedUnauthorizedTemplateChecker|TestRunWithRegistry|TestLoadBuiltinUnauthorizedTemplates|TestUnauthorizedTemplateChecker|TestSecprobe' -v
```

Expected: PASS with memcached using `lookupAtomicUnauthorized(...)` and no regressions in metadata/assets loading.

- [ ] **Step 5: Commit the memcached migration**

```bash
git add pkg/secprobe/default_registry.go pkg/secprobe/default_registry_test.go pkg/secprobe/run_test.go pkg/secprobe/assets_test.go README.md
git commit -m "feat(secprobe): 完成 memcached 未授权模板执行器接入"
```

---

## Self-Review Checklist

### Spec coverage

- YAML remains declarative: request bytes and matchers only, no loops or control flow.
- Engine/executor owns network I/O and error classification.
- Template scope is deliberately bounded to “simple unauthorized” protocols.
- `memcached` migrates; `zookeeper` stays out of scope by design.

### Placeholder scan

- Every task includes exact files and concrete schema or code snippets.
- No step says “generalize later” without a concrete current behavior.
- All verification commands are explicit and scoped.

### Type consistency

- Metadata template reference is `Templates.Unauthorized`.
- Template loader type is `UnauthorizedTemplate`.
- Executor returns `registrybridge.Attempt` with `result.FindingTypeUnauthorizedAccess`.

