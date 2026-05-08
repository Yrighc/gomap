# secprobe Shared Password Dictionary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace per-protocol credential dictionaries with one shared password pool plus thin protocol-level dictionary declarations.

**Architecture:** This is a breaking version iteration. Remove the old `default_sources` and `DictDir` dictionary override paths instead of preserving compatibility. Protocol YAML declares default users, one shared password source, small extra protocol passwords, and exact default pairs; the generator owns the fixed assembly flow and plugins remain atomic authentication only.

**Tech Stack:** Go, YAML metadata under `app/secprobe/protocols`, embedded assets in `app`, credential generation in `pkg/secprobe/credentials`, scan planning in `pkg/secprobe/strategy`, public options in `pkg/secprobe/core`, and Go `testing`.

---

## Scope Decisions

This plan intentionally removes old configuration surfaces:

- Remove `dictionary.default_sources` from protocol YAML.
- Remove per-protocol built-in credential files under `app/secprobe/dicts/*.txt`.
- Remove `CredentialProbeOptions.DictDir` and the CLI/docs behavior around `-weak-dict-dir`.
- Keep explicit `CredentialProbeOptions.Credentials` as the only caller-provided credential input.
- Keep tier semantics, but apply them mainly to the shared password pool.
- Keep inline credentials literal: dedupe only, no expansion.

The new model has exactly one normal dictionary path:

```yaml
dictionary:
  default_users:
    - root
    - admin
  password_source: builtin:passwords/global
  extra_passwords:
    - redis
  default_pairs:
    - username: scott
      password: tiger
  default_tiers:
    - top
    - common
  allow_empty_username: false
  allow_empty_password: false
  expansion_profile: user_password_basic
```

---

## File Map

### Metadata schema and protocol catalog

- Modify: `pkg/secprobe/metadata/spec.go`
- Modify: `pkg/secprobe/metadata/loader.go`
- Modify: `pkg/secprobe/metadata/loader_test.go`
- Modify: `pkg/secprobe/protocol_catalog.go`
- Modify: `pkg/secprobe/protocol_catalog_test.go`

### Shared password source and generator

- Modify: `pkg/secprobe/credentials/types.go`
- Modify: `pkg/secprobe/credentials/generator.go`
- Modify: `pkg/secprobe/credentials/sources.go`
- Modify: `pkg/secprobe/credentials/profile_test.go`
- Modify: `pkg/secprobe/credentials/generator_test.go`
- Modify: `pkg/secprobe/credentials/sources_test.go`
- Create: `app/secprobe/dicts/passwords/global.txt`
- Modify: `app/assets.go`
- Modify: `app/assets_test.go`

### Public options, planner, and run path

- Modify: `pkg/secprobe/core/types.go`
- Modify: `pkg/secprobe/run.go`
- Modify: `pkg/secprobe/run_test.go`
- Modify: `pkg/secprobe/run_state_test.go`
- Modify: `pkg/secprobe/strategy/planner.go`
- Modify: `pkg/secprobe/strategy/planner_test.go`

### Protocol YAML and old dictionary removal

- Modify: `app/secprobe/protocols/*.yaml`
- Delete: `app/secprobe/dicts/amqp.txt`
- Delete: `app/secprobe/dicts/ftp.txt`
- Delete: `app/secprobe/dicts/mongodb.txt`
- Delete: `app/secprobe/dicts/mssql.txt`
- Delete: `app/secprobe/dicts/mysql.txt`
- Delete: `app/secprobe/dicts/oracle.txt`
- Delete: `app/secprobe/dicts/postgresql.txt`
- Delete: `app/secprobe/dicts/rdp.txt`
- Delete: `app/secprobe/dicts/redis.txt`
- Delete: `app/secprobe/dicts/smb.txt`
- Delete: `app/secprobe/dicts/smtp.txt`
- Delete: `app/secprobe/dicts/snmp.txt`
- Delete: `app/secprobe/dicts/ssh.txt`
- Delete: `app/secprobe/dicts/telnet.txt`
- Delete: `app/secprobe/dicts/vnc.txt`

### Documentation

- Modify: `README.md`
- Modify: `docs/secprobe-protocol-extension-guide.md`
- Modify: `docs/secprobe-third-party-migration-guide.md`

---

## Task 1: Replace Metadata Schema With the New Dictionary Model

**Files:**
- Modify: `pkg/secprobe/metadata/spec.go`
- Modify: `pkg/secprobe/metadata/loader.go`
- Modify: `pkg/secprobe/metadata/loader_test.go`

- [ ] **Step 1: Write failing loader tests for the new fields**

Update `pkg/secprobe/metadata/loader_test.go` by replacing the old default-source normalization tests with:

```go
func TestNormalizeSpecNormalizesNewDictionaryFields(t *testing.T) {
	spec := normalizeSpec(Spec{
		Name:    " Redis ",
		Aliases: []string{" Redis/TLS ", "", "REDIS/SSL"},
		Dictionary: Dictionary{
			DefaultUsers:   []string{" Default ", "", "ROOT"},
			PasswordSource: " Builtin:Passwords/Global ",
			ExtraPasswords: []string{" Redis ", "", "Default "},
			DefaultPairs: []CredentialPair{
				{Username: " Scott ", Password: " tiger "},
				{Username: "", Password: "ignored"},
			},
			DefaultTiers: []string{" Top ", "", "COMMON "},
		},
		Templates: TemplateRefs{Unauthorized: " Redis "},
	})

	if spec.Name != "redis" {
		t.Fatalf("expected normalized name redis, got %q", spec.Name)
	}
	if !slices.Equal(spec.Aliases, []string{"redis/tls", "redis/ssl"}) {
		t.Fatalf("expected normalized aliases, got %v", spec.Aliases)
	}
	if !slices.Equal(spec.Dictionary.DefaultUsers, []string{"default", "root"}) {
		t.Fatalf("expected normalized default users, got %v", spec.Dictionary.DefaultUsers)
	}
	if spec.Dictionary.PasswordSource != "builtin:passwords/global" {
		t.Fatalf("expected normalized password source, got %q", spec.Dictionary.PasswordSource)
	}
	if !slices.Equal(spec.Dictionary.ExtraPasswords, []string{"Redis", "Default"}) {
		t.Fatalf("expected trimmed extra passwords preserving case, got %v", spec.Dictionary.ExtraPasswords)
	}
	if len(spec.Dictionary.DefaultPairs) != 1 || spec.Dictionary.DefaultPairs[0].Username != "Scott" || spec.Dictionary.DefaultPairs[0].Password != "tiger" {
		t.Fatalf("expected normalized default pair, got %+v", spec.Dictionary.DefaultPairs)
	}
	if !slices.Equal(spec.Dictionary.DefaultTiers, []string{"top", "common"}) {
		t.Fatalf("expected normalized default tiers, got %v", spec.Dictionary.DefaultTiers)
	}
	if spec.Templates.Unauthorized != "redis" {
		t.Fatalf("expected normalized unauthorized template ref, got %q", spec.Templates.Unauthorized)
	}
}

func TestNormalizeSpecDropsEmptyNewDictionaryFields(t *testing.T) {
	spec := normalizeSpec(Spec{
		Name: "ssh",
		Dictionary: Dictionary{
			DefaultUsers:   []string{"", " ", "\t"},
			PasswordSource: "  ",
			ExtraPasswords: []string{"", " "},
			DefaultPairs: []CredentialPair{
				{Username: "", Password: "x"},
				{Username: "root", Password: ""},
			},
			DefaultTiers: []string{"", " ", "\n"},
		},
	})

	if spec.Dictionary.DefaultUsers != nil {
		t.Fatalf("expected empty default users to normalize to nil, got %v", spec.Dictionary.DefaultUsers)
	}
	if spec.Dictionary.PasswordSource != "" {
		t.Fatalf("expected empty password source, got %q", spec.Dictionary.PasswordSource)
	}
	if spec.Dictionary.ExtraPasswords != nil {
		t.Fatalf("expected empty extra passwords to normalize to nil, got %v", spec.Dictionary.ExtraPasswords)
	}
	if spec.Dictionary.DefaultPairs != nil {
		t.Fatalf("expected empty default pairs to normalize to nil, got %+v", spec.Dictionary.DefaultPairs)
	}
	if spec.Dictionary.DefaultTiers != nil {
		t.Fatalf("expected empty default tiers to normalize to nil, got %v", spec.Dictionary.DefaultTiers)
	}
}
```

- [ ] **Step 2: Run metadata tests and confirm failure**

Run:

```bash
go test ./pkg/secprobe/metadata -run 'TestNormalizeSpecNormalizesNewDictionaryFields|TestNormalizeSpecDropsEmptyNewDictionaryFields' -count=1 -v
```

Expected: FAIL because `Dictionary` does not define `DefaultUsers`, `PasswordSource`, `ExtraPasswords`, or `DefaultPairs`.

- [ ] **Step 3: Update metadata types**

Change `pkg/secprobe/metadata/spec.go`:

```go
type Dictionary struct {
	DefaultUsers       []string         `yaml:"default_users"`
	PasswordSource    string           `yaml:"password_source"`
	ExtraPasswords    []string         `yaml:"extra_passwords"`
	DefaultPairs       []CredentialPair `yaml:"default_pairs"`
	DefaultTiers       []string         `yaml:"default_tiers"`
	AllowEmptyUsername bool             `yaml:"allow_empty_username"`
	AllowEmptyPassword bool             `yaml:"allow_empty_password"`
	ExpansionProfile   string           `yaml:"expansion_profile"`
}

type CredentialPair struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}
```

Remove `DefaultSources []string`.

- [ ] **Step 4: Update normalization**

Change `normalizeSpec` in `pkg/secprobe/metadata/loader.go`:

```go
func normalizeSpec(spec Spec) Spec {
	spec.Name = strings.ToLower(strings.TrimSpace(spec.Name))
	spec.Aliases = normalizeStrings(spec.Aliases)
	spec.Dictionary.DefaultUsers = normalizeStrings(spec.Dictionary.DefaultUsers)
	spec.Dictionary.PasswordSource = strings.ToLower(strings.TrimSpace(spec.Dictionary.PasswordSource))
	spec.Dictionary.ExtraPasswords = normalizePasswords(spec.Dictionary.ExtraPasswords)
	spec.Dictionary.DefaultPairs = normalizeCredentialPairs(spec.Dictionary.DefaultPairs)
	spec.Dictionary.DefaultTiers = normalizeStrings(spec.Dictionary.DefaultTiers)
	spec.Templates.Unauthorized = strings.ToLower(strings.TrimSpace(spec.Templates.Unauthorized))
	return spec
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

func normalizeCredentialPairs(values []CredentialPair) []CredentialPair {
	if len(values) == 0 {
		return nil
	}
	out := make([]CredentialPair, 0, len(values))
	for _, value := range values {
		user := strings.TrimSpace(value.Username)
		pass := strings.TrimSpace(value.Password)
		if user == "" || pass == "" {
			continue
		}
		out = append(out, CredentialPair{Username: user, Password: pass})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
```

- [ ] **Step 5: Run metadata tests**

Run:

```bash
go test ./pkg/secprobe/metadata -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit metadata schema change**

```bash
git add pkg/secprobe/metadata/spec.go pkg/secprobe/metadata/loader.go pkg/secprobe/metadata/loader_test.go
git commit -m "feat(secprobe): 重构弱口令字典元数据模型"
```

---

## Task 2: Add the Shared Password Asset and Remove Per-Protocol Builtin Dict Assets

**Files:**
- Create: `app/secprobe/dicts/passwords/global.txt`
- Modify: `app/assets.go`
- Modify: `app/assets_test.go`
- Delete: `app/secprobe/dicts/*.txt`

- [ ] **Step 1: Write failing asset test for the global password pool**

Update `app/assets_test.go` with:

```go
func TestEmbeddedSecprobeGlobalPasswordPoolLoads(t *testing.T) {
	data, err := SecprobePasswordSource("builtin:passwords/global")
	if err != nil {
		t.Fatalf("SecprobePasswordSource() error = %v", err)
	}
	content := string(data)
	for _, want := range []string{"123456", "{user}", "[common] {user}@123"} {
		if !strings.Contains(content, want) {
			t.Fatalf("expected global password pool to contain %q, got %q", want, content)
		}
	}
}
```

Ensure the file imports `strings`.

- [ ] **Step 2: Run asset test and confirm failure**

Run:

```bash
go test ./app -run TestEmbeddedSecprobeGlobalPasswordPoolLoads -count=1 -v
```

Expected: FAIL because `SecprobePasswordSource` does not exist.

- [ ] **Step 3: Create global password pool**

Create `app/secprobe/dicts/passwords/global.txt`:

```text
123456
admin
password
{user}
{user}123
[common] {user}@123
[common] {user}_123
[extended] Passw0rd
```

- [ ] **Step 4: Update embedded assets**

Change the `//go:embed` line in `app/assets.go` so it embeds `secprobe/dicts/passwords/global.txt` instead of each `secprobe/dicts/<protocol>.txt`.

Add:

```go
func SecprobePasswordSource(source string) ([]byte, error) {
	switch source {
	case "builtin:passwords/global":
		return files.ReadFile("secprobe/dicts/passwords/global.txt")
	default:
		return nil, fmt.Errorf("unsupported secprobe password source: %s", source)
	}
}
```

Remove `SecprobeDict(protocol string)`.

- [ ] **Step 5: Delete old per-protocol dictionaries**

Delete these files:

```text
app/secprobe/dicts/amqp.txt
app/secprobe/dicts/ftp.txt
app/secprobe/dicts/mongodb.txt
app/secprobe/dicts/mssql.txt
app/secprobe/dicts/mysql.txt
app/secprobe/dicts/oracle.txt
app/secprobe/dicts/postgresql.txt
app/secprobe/dicts/rdp.txt
app/secprobe/dicts/redis.txt
app/secprobe/dicts/smb.txt
app/secprobe/dicts/smtp.txt
app/secprobe/dicts/snmp.txt
app/secprobe/dicts/ssh.txt
app/secprobe/dicts/telnet.txt
app/secprobe/dicts/vnc.txt
```

- [ ] **Step 6: Update old asset tests**

Replace any test that calls `SecprobeDict(protocol)` with assertions against `SecprobePasswordSource("builtin:passwords/global")`.

- [ ] **Step 7: Run asset tests**

Run:

```bash
go test ./app -count=1
```

Expected: PASS.

- [ ] **Step 8: Commit asset change**

```bash
git add app/assets.go app/assets_test.go app/secprobe/dicts
git commit -m "feat(secprobe): 使用全局共享密码池替代协议字典"
```

---

## Task 3: Rebuild Credential Profiles and Source Loading Around the New Model

**Files:**
- Modify: `pkg/secprobe/credentials/types.go`
- Modify: `pkg/secprobe/credentials/generator.go`
- Modify: `pkg/secprobe/credentials/sources.go`
- Modify: `pkg/secprobe/credentials/profile_test.go`
- Modify: `pkg/secprobe/credentials/sources_test.go`

- [ ] **Step 1: Write failing profile tests**

Replace default-source profile expectations in `pkg/secprobe/credentials/profile_test.go` with:

```go
func TestProfileFromDictionaryUsesSharedPasswordModel(t *testing.T) {
	got := ProfileFromDictionary(" SSH ", DictionaryProfileInput{
		DefaultUsers:       []string{"root", "admin"},
		PasswordSource:     "builtin:passwords/global",
		ExtraPasswords:     []string{"ssh"},
		DefaultPairs:        []CredentialPair{{Username: "root", Password: "toor"}},
		DefaultTiers:        []string{"top", "common"},
		AllowEmptyPassword: true,
		ExpansionProfile:   "user_password_basic",
	})

	want := CredentialProfile{
		Protocol:           "ssh",
		DefaultUsers:       []string{"root", "admin"},
		PasswordSource:     "builtin:passwords/global",
		ExtraPasswords:     []string{"ssh"},
		DefaultPairs:        []CredentialPair{{Username: "root", Password: "toor"}},
		DefaultTiers:        []Tier{TierTop, TierCommon},
		ScanProfile:        ScanProfileDefault,
		AllowEmptyPassword: true,
		ExpansionProfile:   "user_password_basic",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ProfileFromDictionary() = %#v, want %#v", got, want)
	}
}
```

- [ ] **Step 2: Run profile test and confirm failure**

Run:

```bash
go test ./pkg/secprobe/credentials -run TestProfileFromDictionaryUsesSharedPasswordModel -count=1 -v
```

Expected: FAIL because the profile types still contain `DefaultSources`.

- [ ] **Step 3: Update credential profile types**

In `pkg/secprobe/credentials/types.go`, replace `DefaultSources` with:

```go
type CredentialPair struct {
	Username string
	Password string
}

type CredentialProfile struct {
	Protocol           string
	DefaultUsers       []string
	PasswordSource     string
	ExtraPasswords     []string
	DefaultPairs        []CredentialPair
	DefaultTiers        []Tier
	ScanProfile        ScanProfile
	AllowEmptyUsername bool
	AllowEmptyPassword bool
	ExpansionProfile   string
}
```

- [ ] **Step 4: Update profile construction**

In `pkg/secprobe/credentials/generator.go`, change `DictionaryProfileInput`:

```go
type DictionaryProfileInput struct {
	DefaultUsers       []string
	PasswordSource     string
	ExtraPasswords     []string
	DefaultPairs        []CredentialPair
	DefaultTiers        []string
	AllowEmptyUsername bool
	AllowEmptyPassword bool
	ExpansionProfile   string
}
```

Change `ProfileFromMetadata` to map metadata pairs:

```go
func ProfileFromMetadata(protocol string, dict metadata.Dictionary) CredentialProfile {
	return ProfileFromDictionary(protocol, DictionaryProfileInput{
		DefaultUsers:       dict.DefaultUsers,
		PasswordSource:     dict.PasswordSource,
		ExtraPasswords:     dict.ExtraPasswords,
		DefaultPairs:        metadataPairsToCredentialPairs(dict.DefaultPairs),
		DefaultTiers:        dict.DefaultTiers,
		AllowEmptyUsername: dict.AllowEmptyUsername,
		AllowEmptyPassword: dict.AllowEmptyPassword,
		ExpansionProfile:   dict.ExpansionProfile,
	})
}

func metadataPairsToCredentialPairs(values []metadata.CredentialPair) []CredentialPair {
	out := make([]CredentialPair, 0, len(values))
	for _, value := range values {
		out = append(out, CredentialPair{Username: value.Username, Password: value.Password})
	}
	return out
}
```

Change `ProfileFromDictionary` to fill the new fields and default `PasswordSource` to `builtin:passwords/global` when blank.

- [ ] **Step 5: Replace source loader behavior**

In `pkg/secprobe/credentials/sources.go`:

- Remove `LoadDirectorySource`, `LoadDirectorySourceByTiers`, `LoadBuiltinSource`, `LoadBuiltinSourceByTiers`, `dictionaryCandidatePaths`, `builtinSourceCandidates`, and `protocolDictionaryProfile`.
- Replace `builtinEntryLoader` with a password-source loader:

```go
var builtinPasswordEntryLoader = func(source string) ([]credentialEntry, error) {
	data, err := appassets.SecprobePasswordSource(source)
	if err != nil {
		return nil, err
	}
	return parsePasswordEntries(string(data))
}
```

Add:

```go
func LoadPasswordSourceByTiers(source string, tiers []Tier) ([]credentialEntry, SourceDescriptor, error) {
	entries, err := builtinPasswordEntryLoader(source)
	if err != nil {
		return nil, SourceDescriptor{}, &missingSourceError{kind: SourceBuiltin, target: source, err: err}
	}
	filtered := filterCredentialEntriesByTiers(entries, tiers)
	if len(filtered) == 0 {
		return nil, SourceDescriptor{}, &missingSourceError{kind: SourceBuiltin, target: source, err: os.ErrNotExist}
	}
	return filtered, SourceDescriptor{Kind: SourceBuiltin, Name: source}, nil
}

func parsePasswordEntries(raw string) ([]credentialEntry, error) {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	out := make([]credentialEntry, 0, len(lines))
	for idx, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		tier := TierTop
		content := trimmed
		if strings.HasPrefix(trimmed, "[") {
			end := strings.Index(trimmed, "]")
			if end <= 1 {
				return nil, fmt.Errorf("invalid password tier line %d: %q", idx+1, line)
			}
			tier = normalizeTier(Tier(trimmed[1:end]))
			if tier == "" {
				return nil, fmt.Errorf("invalid password tier line %d: %q", idx+1, line)
			}
			content = strings.TrimSpace(trimmed[end+1:])
		}
		if content == "" {
			continue
		}
		out = append(out, credentialEntry{Tier: tier, Credential: strategy.Credential{Password: content}})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid passwords found")
	}
	return out, nil
}
```

Keep `parseStrategyCredentialEntries` only if tests or inline pair parsing still need it; otherwise remove it with the old protocol dictionary path.

- [ ] **Step 6: Run credential package tests**

Run:

```bash
go test ./pkg/secprobe/credentials -count=1
```

Expected: FAIL only in generator tests that still expect old protocol dictionaries. Those are rewritten in Task 4.

- [ ] **Step 7: Commit profile and source changes**

```bash
git add pkg/secprobe/credentials
git commit -m "feat(secprobe): 改造凭据配置为共享密码模型"
```

---

## Task 4: Implement New Generator Assembly Flow

**Files:**
- Modify: `pkg/secprobe/credentials/generator.go`
- Modify: `pkg/secprobe/credentials/generator_test.go`

- [ ] **Step 1: Replace generator tests with new model tests**

Rewrite `pkg/secprobe/credentials/generator_test.go` around these behaviors:

```go
func TestGeneratorBuildsCredentialsFromUsersSharedPasswordsExtraPasswordsAndPairs(t *testing.T) {
	restore := stubBuiltinPasswordEntryLoader(func(source string) ([]credentialEntry, error) {
		if source != "builtin:passwords/global" {
			t.Fatalf("source = %q, want builtin:passwords/global", source)
		}
		return []credentialEntry{
			{Tier: TierTop, Credential: strategy.Credential{Password: "123456"}},
			{Tier: TierCommon, Credential: strategy.Credential{Password: "{user}123"}},
			{Tier: TierExtended, Credential: strategy.Credential{Password: "Passw0rd"}},
		}, nil
	})
	defer restore()

	gen := Generator{}
	got, meta, err := gen.Generate(GenerateInput{
		Profile: CredentialProfile{
			Protocol:           "redis",
			DefaultUsers:       []string{""},
			PasswordSource:     "builtin:passwords/global",
			ExtraPasswords:     []string{"redis"},
			DefaultPairs:        []CredentialPair{{Username: "default", Password: "default"}},
			DefaultTiers:        []Tier{TierTop, TierCommon},
			ScanProfile:        ScanProfileDefault,
			AllowEmptyUsername: true,
			AllowEmptyPassword: true,
			ExpansionProfile:   "static_basic",
		},
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	want := []strategy.Credential{
		{Username: "", Password: "123456"},
		{Username: "", Password: "123"},
		{Username: "", Password: "redis"},
		{Username: "default", Password: "default"},
		{Username: "", Password: ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Generate() creds = %#v, want %#v", got, want)
	}
	if meta.Source.Kind != SourceBuiltin || meta.Source.Name != "builtin:passwords/global" {
		t.Fatalf("Generate() source = %+v", meta.Source)
	}
	if !reflect.DeepEqual(meta.SelectedTiers, []Tier{TierTop, TierCommon}) {
		t.Fatalf("Generate() tiers = %v", meta.SelectedTiers)
	}
}

func TestGeneratorKeepsInlineCredentialsLiteralWithoutExpansion(t *testing.T) {
	gen := Generator{}
	got, meta, err := gen.Generate(GenerateInput{
		Profile: CredentialProfile{
			Protocol:           "redis",
			DefaultUsers:       []string{""},
			PasswordSource:     "builtin:passwords/global",
			AllowEmptyUsername: true,
			AllowEmptyPassword: true,
			ExpansionProfile:   "static_basic",
		},
		Inline: []strategy.Credential{
			{Username: "admin", Password: "admin"},
			{Username: "admin", Password: "admin"},
		},
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	want := []strategy.Credential{{Username: "admin", Password: "admin"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Generate() creds = %v, want %v", got, want)
	}
	if meta.Source.Kind != SourceInline {
		t.Fatalf("Generate() source = %+v, want inline", meta.Source)
	}
}

func TestGeneratorReturnsNoCredentialsWhenPasswordSourceFiltersToEmpty(t *testing.T) {
	restore := stubBuiltinPasswordEntryLoader(func(string) ([]credentialEntry, error) {
		return []credentialEntry{{Tier: TierExtended, Credential: strategy.Credential{Password: "extended"}}}, nil
	})
	defer restore()

	gen := Generator{}
	_, _, err := gen.Generate(GenerateInput{
		Profile: CredentialProfile{
			Protocol:       "ssh",
			DefaultUsers:   []string{"root"},
			PasswordSource: "builtin:passwords/global",
			DefaultTiers:   []Tier{TierTop},
			ScanProfile:    ScanProfileFast,
		},
	})
	if err == nil || !IsMissingSource(err) {
		t.Fatalf("expected missing source error, got %v", err)
	}
}
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
go test ./pkg/secprobe/credentials -run 'TestGeneratorBuildsCredentialsFromUsersSharedPasswordsExtraPasswordsAndPairs|TestGeneratorKeepsInlineCredentialsLiteralWithoutExpansion|TestGeneratorReturnsNoCredentialsWhenPasswordSourceFiltersToEmpty' -count=1 -v
```

Expected: FAIL because generator still loads protocol dictionaries and has `DictDir`.

- [ ] **Step 3: Remove DictDir from GenerateInput**

Change `GenerateInput`:

```go
type GenerateInput struct {
	Profile CredentialProfile
	Inline  []strategy.Credential
}
```

- [ ] **Step 4: Implement fixed assembly flow**

Replace the non-inline branch in `Generator.Generate` with:

```go
passwordEntries, source, err := LoadPasswordSourceByTiers(in.Profile.PasswordSource, selectedTiers)
if err != nil {
	return nil, GenerateMeta{}, err
}
meta.Source = source

passwords := flattenCredentialEntries(passwordEntries)
base := buildUserPasswordCredentials(in.Profile.DefaultUsers, passwords)
base = append(base, buildUserPasswordCredentials(in.Profile.DefaultUsers, passwordStringsToCredentials(in.Profile.ExtraPasswords))...)
base = append(base, credentialPairsToStrategy(in.Profile.DefaultPairs)...)

return Expand(base, Options{
	Profile:        in.Profile.ExpansionProfile,
	AllowEmptyUser: in.Profile.AllowEmptyUsername,
	AllowEmptyPass: in.Profile.AllowEmptyPassword,
}), meta, nil
```

Add helpers:

```go
func buildUserPasswordCredentials(users []string, passwords []strategy.Credential) []strategy.Credential {
	out := make([]strategy.Credential, 0, len(users)*len(passwords))
	for _, user := range users {
		for _, password := range passwords {
			out = append(out, strategy.Credential{Username: user, Password: strings.ReplaceAll(password.Password, "{user}", user)})
		}
	}
	return out
}

func passwordStringsToCredentials(values []string) []strategy.Credential {
	out := make([]strategy.Credential, 0, len(values))
	for _, value := range values {
		out = append(out, strategy.Credential{Password: value})
	}
	return out
}

func credentialPairsToStrategy(values []CredentialPair) []strategy.Credential {
	out := make([]strategy.Credential, 0, len(values))
	for _, value := range values {
		out = append(out, strategy.Credential{Username: value.Username, Password: value.Password})
	}
	return out
}
```

Keep final dedupe behavior in `Expand`; if `Expand` does not dedupe generated credentials, run generated output through `dedupeStrategyCredentials` before returning.

- [ ] **Step 5: Run credential tests**

Run:

```bash
go test ./pkg/secprobe/credentials -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit generator change**

```bash
git add pkg/secprobe/credentials
git commit -m "feat(secprobe): 实现共享密码池凭据生成流程"
```

---

## Task 5: Remove DictDir From Public Options and Strategy Planning

**Files:**
- Modify: `pkg/secprobe/core/types.go`
- Modify: `pkg/secprobe/run.go`
- Modify: `pkg/secprobe/run_test.go`
- Modify: `pkg/secprobe/run_state_test.go`
- Modify: `pkg/secprobe/strategy/planner.go`
- Modify: `pkg/secprobe/strategy/planner_test.go`

- [ ] **Step 1: Write failing planner test for simplified dictionary source**

Update `pkg/secprobe/strategy/planner_test.go` to remove DictDir cases and add:

```go
func TestCompileCredentialDictionarySetUsesMetadataOnly(t *testing.T) {
	plan, err := Compile(CompileInput{
		Candidate: Candidate{Service: "ssh"},
		Spec: Spec{
			Name: "ssh",
			Capabilities: Capabilities{Credential: true},
			Dictionary: Dictionary{
				PasswordSource: "builtin:passwords/global",
				DefaultTiers:   []string{"top", "common"},
			},
		},
	})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if len(plan.CredentialSets) != 1 {
		t.Fatalf("expected one credential set, got %+v", plan.CredentialSets)
	}
	got := plan.CredentialSets[0]
	if got.Source != SourceBuiltin || got.Directory != "" {
		t.Fatalf("expected builtin metadata credential set without directory, got %+v", got)
	}
	if !slices.Equal(got.Dictionaries, []string{"builtin:passwords/global"}) {
		t.Fatalf("expected password source dictionary, got %v", got.Dictionaries)
	}
}
```

- [ ] **Step 2: Run planner test and confirm failure**

Run:

```bash
go test ./pkg/secprobe/strategy -run TestCompileCredentialDictionarySetUsesMetadataOnly -count=1 -v
```

Expected: FAIL because planner still references `DictDir` and `DefaultSources`.

- [ ] **Step 3: Remove DictDir fields**

Remove `DictDir` from:

- `pkg/secprobe/core/types.go` `CredentialProbeOptions`
- `pkg/secprobe/strategy/planner.go` `CompileInput`
- any `GenerateInput` construction in `pkg/secprobe/run.go`

Remove helper functions that only load credentials from a directory:

- `loadCredentialsFromDir`
- `translateCredentialGenerationError` branches that mention `DictDir`
- tests that assert explicit missing `dict_dir` behavior

- [ ] **Step 4: Update planner dictionary set mapping**

Change planner dictionary metadata mapping from `DefaultSources` to `PasswordSource`:

```go
Dictionaries: []string{spec.Dictionary.PasswordSource},
```

If `PasswordSource` is empty for a non-credential protocol, produce no credential set. If it is empty for a credential protocol, let compile return a clear error:

```go
if spec.Capabilities.Credential && strings.TrimSpace(spec.Dictionary.PasswordSource) == "" {
	return Plan{}, fmt.Errorf("credential protocol %q missing dictionary.password_source", spec.Name)
}
```

- [ ] **Step 5: Update run tests**

Remove or rewrite tests named around:

- `DictDir`
- `weak-dict-dir`
- missing dict dir fallback
- directory before builtin priority

Keep tests for:

- explicit credentials are literal
- generated credentials use builtin global password source
- no credentials maps to `no-credentials`

- [ ] **Step 6: Run affected tests**

Run:

```bash
go test ./pkg/secprobe ./pkg/secprobe/strategy -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit public option simplification**

```bash
git add pkg/secprobe/core pkg/secprobe/run.go pkg/secprobe/*_test.go pkg/secprobe/strategy
git commit -m "feat(secprobe): 移除弱口令目录覆盖配置"
```

---

## Task 6: Migrate Protocol YAML to Thin Dictionary Declarations

**Files:**
- Modify: `app/secprobe/protocols/amqp.yaml`
- Modify: `app/secprobe/protocols/ftp.yaml`
- Modify: `app/secprobe/protocols/mongodb.yaml`
- Modify: `app/secprobe/protocols/mssql.yaml`
- Modify: `app/secprobe/protocols/mysql.yaml`
- Modify: `app/secprobe/protocols/oracle.yaml`
- Modify: `app/secprobe/protocols/postgresql.yaml`
- Modify: `app/secprobe/protocols/rdp.yaml`
- Modify: `app/secprobe/protocols/redis.yaml`
- Modify: `app/secprobe/protocols/smb.yaml`
- Modify: `app/secprobe/protocols/smtp.yaml`
- Modify: `app/secprobe/protocols/snmp.yaml`
- Modify: `app/secprobe/protocols/ssh.yaml`
- Modify: `app/secprobe/protocols/telnet.yaml`
- Modify: `app/secprobe/protocols/vnc.yaml`

- [ ] **Step 1: Update YAML tests to assert new model**

In `pkg/secprobe/metadata/loader_test.go`, add:

```go
func TestBuiltinCredentialSpecsUseSharedPasswordModel(t *testing.T) {
	specs, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin() error = %v", err)
	}

	for _, name := range []string{"ssh", "mysql", "redis", "telnet", "ftp", "mongodb", "mssql", "postgresql", "rdp", "smb", "smtp", "snmp", "vnc", "amqp", "oracle"} {
		spec := specs[name]
		if !spec.Capabilities.Credential {
			t.Fatalf("%s should be credential-capable for this assertion", name)
		}
		if spec.Dictionary.PasswordSource != "builtin:passwords/global" {
			t.Fatalf("%s password source = %q", name, spec.Dictionary.PasswordSource)
		}
		if len(spec.Dictionary.DefaultUsers) == 0 && len(spec.Dictionary.DefaultPairs) == 0 {
			t.Fatalf("%s must define default_users or default_pairs", name)
		}
	}
}
```

- [ ] **Step 2: Run YAML test and confirm failure**

Run:

```bash
go test ./pkg/secprobe/metadata -run TestBuiltinCredentialSpecsUseSharedPasswordModel -count=1 -v
```

Expected: FAIL because YAML files still use `default_sources`.

- [ ] **Step 3: Migrate credential protocol YAML**

For every credential-capable protocol, remove `default_sources` and add:

```yaml
dictionary:
  default_users:
    - root
  password_source: builtin:passwords/global
  default_tiers:
    - top
    - common
  allow_empty_username: false
  allow_empty_password: false
  expansion_profile: static_basic
```

Use these initial default users and exceptions:

```text
amqp: default_users=[guest admin], default_pairs=[guest:guest]
ftp: default_users=[ftp admin root www web], default_pairs=[anonymous:anonymous]
mongodb: default_users=[root admin]
mssql: default_users=[sa sql]
mysql: default_users=[root mysql]
oracle: default_users=[sys system admin test web orcl], default_pairs=[scott:tiger system:manager sys:sys]
postgresql: default_users=[postgres admin]
rdp: default_users=[administrator admin guest]
redis: default_users=[""], extra_passwords=[redis default], allow_empty_username=true, allow_empty_password=true
smb: default_users=[administrator admin guest]
smtp: default_users=[admin root postmaster mail smtp administrator]
snmp: default_users=[""], extra_passwords=[public private default], allow_empty_username=true
ssh: default_users=[root admin], allow_empty_password=true, expansion_profile=user_password_basic
telnet: default_users=[root admin test]
vnc: default_users=[""], extra_passwords=[vnc], allow_empty_username=true
```

For unauthorized-only protocols such as `memcached` and `zookeeper`, keep:

```yaml
dictionary:
  allow_empty_username: false
  allow_empty_password: false
  expansion_profile: none
```

Do not add `password_source` to unauthorized-only protocols.

- [ ] **Step 4: Run metadata tests**

Run:

```bash
go test ./pkg/secprobe/metadata -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit YAML migration**

```bash
git add app/secprobe/protocols pkg/secprobe/metadata/loader_test.go
git commit -m "feat(secprobe): 迁移协议元数据到共享密码模型"
```

---

## Task 7: Update Protocol Catalog and Documentation Surfaces

**Files:**
- Modify: `pkg/secprobe/protocol_catalog.go`
- Modify: `pkg/secprobe/protocol_catalog_test.go`
- Modify: `README.md`
- Modify: `docs/secprobe-protocol-extension-guide.md`
- Modify: `docs/secprobe-third-party-migration-guide.md`

- [ ] **Step 1: Update catalog tests**

In `pkg/secprobe/protocol_catalog_test.go`, replace `DictNames` expectations with a single password source expectation:

```go
func TestProtocolCatalogExposesSharedPasswordSource(t *testing.T) {
	specs := map[string]metadata.Spec{
		"ssh": {
			Name: "ssh",
			Capabilities: metadata.Capabilities{Credential: true},
			Dictionary: metadata.Dictionary{
				DefaultUsers:   []string{"root", "admin"},
				PasswordSource: "builtin:passwords/global",
				DefaultTiers:   []string{"top", "common"},
			},
		},
	}

	got := buildProtocolCatalog(specs)
	ssh := got["ssh"]
	if ssh.PasswordSource != "builtin:passwords/global" {
		t.Fatalf("expected shared password source, got %+v", ssh)
	}
	if !slices.Equal(ssh.DefaultUsers, []string{"root", "admin"}) {
		t.Fatalf("expected default users, got %+v", ssh)
	}
}
```

- [ ] **Step 2: Run catalog test and confirm failure**

Run:

```bash
go test ./pkg/secprobe -run TestProtocolCatalogExposesSharedPasswordSource -count=1 -v
```

Expected: FAIL because catalog still exposes `DictNames`.

- [ ] **Step 3: Update catalog type and builder**

In `pkg/secprobe/protocol_catalog.go`, replace `DictNames` with:

```go
DefaultUsers   []string `json:"default_users,omitempty"`
PasswordSource string   `json:"password_source,omitempty"`
```

Map from:

```go
DefaultUsers: append([]string(nil), spec.Dictionary.DefaultUsers...),
PasswordSource: spec.Dictionary.PasswordSource,
```

- [ ] **Step 4: Update docs**

Make these documentation changes:

- Replace `inline > dict_dir > builtin` with `inline credentials > builtin shared password pool`.
- Replace `default_sources` examples with `default_users` and `password_source`.
- Remove guidance for `DictDir`, `-weak-dict-dir`, and missing directory behavior.
- Add migration note: this version intentionally breaks old per-protocol dictionary configuration.
- State that third-party callers should pass exact `Credentials` for custom attempts.
- State that large custom dictionary injection is not part of this simplified version.

- [ ] **Step 5: Run doc grep checks**

Run:

```bash
rg -n "default_sources|dict_dir|DictDir|weak-dict-dir|inline > dict_dir|SecprobeDict" README.md docs pkg app
```

Expected: no matches except historical docs under `docs/superpowers/`.

- [ ] **Step 6: Run catalog and doc-adjacent tests**

Run:

```bash
go test ./pkg/secprobe -run 'TestProtocolCatalog|TestBuildCandidates|TestRun' -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit catalog and docs**

```bash
git add pkg/secprobe/protocol_catalog.go pkg/secprobe/protocol_catalog_test.go README.md docs/secprobe-protocol-extension-guide.md docs/secprobe-third-party-migration-guide.md
git commit -m "docs(secprobe): 更新共享密码池接入说明"
```

---

## Task 8: Full Verification and Cleanup

**Files:**
- Review all changed files

- [ ] **Step 1: Run repository search for removed surfaces**

Run:

```bash
rg -n "DefaultSources|default_sources|DictDir|dict_dir|weak-dict-dir|LoadDirectorySource|LoadBuiltinSource|SecprobeDict" pkg app README.md docs --glob '!docs/superpowers/**'
```

Expected: no matches.

- [ ] **Step 2: Run focused secprobe tests**

Run:

```bash
go test ./app ./pkg/secprobe ./pkg/secprobe/credentials ./pkg/secprobe/metadata ./pkg/secprobe/strategy -count=1
```

Expected: PASS.

- [ ] **Step 3: Run broader package tests**

Run:

```bash
go test ./pkg/... ./app/... -count=1
```

Expected: PASS.

- [ ] **Step 4: Inspect final diff**

Run:

```bash
git diff --stat HEAD
git diff --check
```

Expected:

- `git diff --check` prints no whitespace errors.
- Diff contains no old per-protocol dictionary files.
- Diff contains the new global password pool.
- Diff contains no `DictDir` public option references.

- [ ] **Step 5: Final commit if cleanup changed files**

If Step 1-4 required cleanup changes, commit them:

```bash
git add .
git commit -m "chore(secprobe): 清理旧弱口令字典入口"
```

If there are no cleanup changes, do not create an empty commit.

---

## Self-Review Checklist

- [ ] Every old dictionary entry path has a replacement in either `default_users`, `extra_passwords`, `default_pairs`, or `passwords/global.txt`.
- [ ] Explicit credentials remain literal and do not pass through expansion.
- [ ] No compatibility fallback remains for `default_sources`.
- [ ] No compatibility fallback remains for `DictDir`.
- [ ] Unauthorized-only protocols do not require `password_source`.
- [ ] Credential-capable protocols have `password_source`.
- [ ] Tests cover metadata parsing, asset embedding, generator assembly, public option simplification, and docs grep cleanup.
