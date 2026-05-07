# secprobe Engine/Metadata Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate the remaining built-in `secprobe` protocol declarations from the hard-coded legacy catalog into `app/secprobe/protocols/*.yaml`, while preserving the current public API, result contract, and protocol lookup behavior introduced in phase 1.

**Architecture:** Reuse the phase-1 metadata boundary: YAML stays strictly declarative, `pkg/secprobe/metadata` remains the single loader, and `pkg/secprobe/protocol_catalog.go` continues to expose the existing `ProtocolSpec` surface. This phase does not migrate additional protocol execution logic to atomic plugins; it only moves protocol identity, capability, port, alias, dictionary, and enrichment declarations into metadata so later phases can retire the legacy catalog in smaller steps.

**Tech Stack:** Go, embedded app assets, existing `pkg/secprobe/metadata` loader, `pkg/secprobe/protocol_catalog.go`, `pkg/secprobe/assets.go`, `pkg/secprobe/dictionaries.go`, Go `testing`, and embedded YAML assets in `app/secprobe/protocols`.

---

## Scope Decomposition

At the start of this phase, only the following protocols already resolve from YAML metadata:

- `redis`
- `ssh`

The following protocols still depend on `legacyProtocolSpecs` and are in scope for migration:

- `ftp`
- `mssql`
- `telnet`
- `smtp`
- `mysql`
- `oracle`
- `rdp`
- `postgresql`
- `amqp`
- `smb`
- `snmp`
- `mongodb`
- `vnc`
- `memcached`
- `zookeeper`

To keep review size manageable and reduce alias/port regressions, this phase is intentionally split into protocol batches that follow the already-proven historical grouping:

1. Batch A: `ftp`, `mssql`, `mysql`, `telnet`
2. Batch B: `postgresql`, `smtp`, `amqp`
3. Batch C: `oracle`, `rdp`, `smb`, `vnc`, `snmp`
4. Batch D: `mongodb`, `memcached`, `zookeeper`
5. Cleanup: shrink the legacy catalog to a narrow fallback set and lock regression coverage

This phase explicitly does **not**:

- add new protocols
- change the public `Run` / `RunWithRegistry` API
- migrate additional protocols to atomic execution
- remove the legacy adapter path
- introduce a template executor for unauthorized checks

---

## File Map

### Shared metadata infrastructure

- Modify: `pkg/secprobe/metadata/loader_test.go`
- Modify: `pkg/secprobe/protocol_catalog_test.go`
- Modify: `pkg/secprobe/protocol_catalog.go`

### Protocol YAML declarations

- Create: `app/secprobe/protocols/ftp.yaml`
- Create: `app/secprobe/protocols/mssql.yaml`
- Create: `app/secprobe/protocols/telnet.yaml`
- Create: `app/secprobe/protocols/smtp.yaml`
- Create: `app/secprobe/protocols/mysql.yaml`
- Create: `app/secprobe/protocols/oracle.yaml`
- Create: `app/secprobe/protocols/rdp.yaml`
- Create: `app/secprobe/protocols/postgresql.yaml`
- Create: `app/secprobe/protocols/amqp.yaml`
- Create: `app/secprobe/protocols/smb.yaml`
- Create: `app/secprobe/protocols/snmp.yaml`
- Create: `app/secprobe/protocols/mongodb.yaml`
- Create: `app/secprobe/protocols/vnc.yaml`
- Create: `app/secprobe/protocols/memcached.yaml`
- Create: `app/secprobe/protocols/zookeeper.yaml`

### Compatibility and regression coverage

- Modify: `pkg/secprobe/assets_test.go`
- Modify: `pkg/secprobe/dictionaries_test.go`
- Modify: `pkg/secprobe/default_registry_test.go`
- Modify: `README.md`

---

## Task 1: Expand Metadata Loader Coverage and Lock the Full Built-in Set

**Files:**
- Modify: `pkg/secprobe/metadata/loader_test.go`
- Modify: `pkg/secprobe/protocol_catalog_test.go`

- [ ] **Step 1: Add failing loader assertions for the remaining built-in protocol names**

Extend `pkg/secprobe/metadata/loader_test.go` with a new test:

```go
func TestLoadSpecsIncludesAllBuiltinProtocolNamesAfterPhase2(t *testing.T) {
	specs, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin() error = %v", err)
	}

	want := []string{
		"amqp", "ftp", "memcached", "mongodb", "mssql", "mysql",
		"oracle", "postgresql", "rdp", "redis", "smb", "smtp",
		"snmp", "ssh", "telnet", "vnc", "zookeeper",
	}

	for _, name := range want {
		if _, ok := specs[name]; !ok {
			t.Fatalf("expected %s spec, got keys %v", name, slices.Sorted(maps.Keys(specs)))
		}
	}
}
```

- [ ] **Step 2: Add a compatibility test and a metadata-only proof point**

Extend `pkg/secprobe/protocol_catalog_test.go` with a focused helper-driven assertion:

```go
func TestLookupProtocolSpecPhase2MetadataMatchesHistoricalLegacyContracts(t *testing.T) {
	tests := []struct {
		service string
		port    int
		want    ProtocolSpec
	}{
		{
			service: "ftp",
			want: ProtocolSpec{
				Name:       "ftp",
				Ports:      []int{21},
				DictNames:  []string{"ftp"},
				ProbeKinds: []ProbeKind{ProbeKindCredential},
			},
		},
		{
			service: "memcached",
			want: ProtocolSpec{
				Name:       "memcached",
				Ports:      []int{11211},
				ProbeKinds: []ProbeKind{ProbeKindUnauthorized},
			},
		},
		{
			service: "mongo",
			want: ProtocolSpec{
				Name:               "mongodb",
				Aliases:            []string{"mongo"},
				Ports:              []int{27017},
				DictNames:          []string{"mongodb", "mongo"},
				ProbeKinds:         []ProbeKind{ProbeKindCredential, ProbeKindUnauthorized},
				SupportsEnrichment: true,
			},
		},
	}

	for _, tt := range tests {
		spec, ok := LookupProtocolSpec(tt.service, tt.port)
		if !ok {
			t.Fatalf("expected protocol spec for %q/%d", tt.service, tt.port)
		}
		if !reflect.DeepEqual(spec, tt.want) {
			t.Fatalf("expected %#v, got %#v", tt.want, spec)
		}
	}
}
```

And add a metadata-loader assertion that proves these declarations actually exist in YAML rather than only resolving through legacy fallback:

```go
func TestLoadSpecsIncludesPhase2HistoricalContracts(t *testing.T) {
	specs, err := metadata.LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin() error = %v", err)
	}

	ftp := specs["ftp"]
	if ftp.Name != "ftp" || !slices.Equal(ftp.Ports, []int{21}) {
		t.Fatalf("expected ftp metadata contract, got %+v", ftp)
	}

	mongodb := specs["mongodb"]
	if !slices.Equal(mongodb.Aliases, []string{"mongo"}) {
		t.Fatalf("expected mongodb alias metadata, got %+v", mongodb)
	}
	if !mongodb.Capabilities.Unauthorized || !mongodb.Capabilities.Credential || !mongodb.Capabilities.Enrichment {
		t.Fatalf("expected mongodb capabilities in metadata, got %+v", mongodb.Capabilities)
	}
}
```

- [ ] **Step 3: Run the metadata and catalog tests to capture the missing-yaml baseline**

Run:

```bash
go test ./pkg/secprobe/metadata ./pkg/secprobe -run 'TestLoadSpecsIncludesAllBuiltinProtocolNamesAfterPhase2|TestLookupProtocolSpecPhase2MetadataMatchesHistoricalLegacyContracts|TestLookupProtocolSpec' -v
```

Expected: FAIL because the new YAML declarations do not exist yet.

---

## Task 2: Add Batch A Metadata (`ftp`, `mssql`, `mysql`, `telnet`)

**Files:**
- Create: `app/secprobe/protocols/ftp.yaml`
- Create: `app/secprobe/protocols/mssql.yaml`
- Create: `app/secprobe/protocols/mysql.yaml`
- Create: `app/secprobe/protocols/telnet.yaml`
- Modify: `pkg/secprobe/metadata/loader_test.go`
- Modify: `pkg/secprobe/protocol_catalog_test.go`

- [ ] **Step 1: Create the first metadata batch with strictly declarative fields**

Create YAML files that mirror the historical catalog contracts:

`app/secprobe/protocols/ftp.yaml`

```yaml
name: ftp
ports:
  - 21
capabilities:
  credential: true
  unauthorized: false
  enrichment: false
policy_tags:
  lockout_risk: medium
  auth_family: password
  transport: tcp
dictionary:
  default_sources:
    - ftp
  allow_empty_username: false
  allow_empty_password: false
  expansion_profile: static_basic
results:
  credential_success_type: credential_valid
  evidence_profile: ftp_basic
```

Follow the same shape for:

- `mssql.yaml`
- `mysql.yaml`
- `telnet.yaml`

Each file must keep:

- the same protocol name as the catalog
- the same default port(s)
- `credential` only capability
- the same builtin dict source name
- a complete metadata shape: `policy_tags.lockout_risk`, `policy_tags.auth_family`, `policy_tags.transport`, `dictionary.allow_empty_username`, `dictionary.allow_empty_password`, `dictionary.expansion_profile`, `results.credential_success_type`, and `results.evidence_profile`

- [ ] **Step 2: Add targeted batch-A catalog assertions**

Extend `pkg/secprobe/protocol_catalog_test.go` with:

```go
func TestLookupProtocolSpecPhase2BatchAMetadataProtocols(t *testing.T) {
	tests := []struct {
		service string
		port    int
		want    ProtocolSpec
	}{
		{service: "ftp", want: ProtocolSpec{Name: "ftp", Ports: []int{21}, DictNames: []string{"ftp"}, ProbeKinds: []ProbeKind{ProbeKindCredential}}},
		{service: "mssql", want: ProtocolSpec{Name: "mssql", Ports: []int{1433}, DictNames: []string{"mssql"}, ProbeKinds: []ProbeKind{ProbeKindCredential}}},
		{port: 3306, want: ProtocolSpec{Name: "mysql", Ports: []int{3306}, DictNames: []string{"mysql"}, ProbeKinds: []ProbeKind{ProbeKindCredential}}},
		{service: "telnet", want: ProtocolSpec{Name: "telnet", Ports: []int{23}, DictNames: []string{"telnet"}, ProbeKinds: []ProbeKind{ProbeKindCredential}}},
	}

	for _, tt := range tests {
		spec, ok := LookupProtocolSpec(tt.service, tt.port)
		if !ok {
			t.Fatalf("expected protocol spec for %q/%d", tt.service, tt.port)
		}
		if !reflect.DeepEqual(spec, tt.want) {
			t.Fatalf("expected %#v, got %#v", tt.want, spec)
		}
	}
}
```

- [ ] **Step 3: Run the batch-A metadata slice**

Run:

```bash
go test ./pkg/secprobe/metadata ./pkg/secprobe -run 'TestLoadSpecsIncludesAllBuiltinProtocolNamesAfterPhase2|TestLookupProtocolSpecPhase2BatchAMetadataProtocols|TestLookupProtocolSpec' -v
```

Expected: PASS for `TestLookupProtocolSpecPhase2BatchAMetadataProtocols` and the existing `TestLookupProtocolSpec...` alias/port coverage that batch A touches. `TestLoadSpecsIncludesAllBuiltinProtocolNamesAfterPhase2` is intentionally not part of this batch gate because it is a final phase-wide assertion.

- [ ] **Step 4: Commit batch-A metadata**

```bash
git add app/secprobe/protocols/ftp.yaml app/secprobe/protocols/mssql.yaml app/secprobe/protocols/mysql.yaml app/secprobe/protocols/telnet.yaml pkg/secprobe/metadata/loader_test.go pkg/secprobe/protocol_catalog_test.go
git commit -m "feat(secprobe): add phase-2 metadata batch a"
```

---

## Task 3: Add Batch B Metadata (`postgresql`, `smtp`, `amqp`)

**Files:**
- Create: `app/secprobe/protocols/postgresql.yaml`
- Create: `app/secprobe/protocols/smtp.yaml`
- Create: `app/secprobe/protocols/amqp.yaml`
- Modify: `pkg/secprobe/protocol_catalog_test.go`

- [ ] **Step 1: Create metadata for alias-heavy credential protocols**

Carry forward the historical alias and dict behavior:

- `postgresql.yaml`
  - aliases: `postgres`, `pgsql`
  - dict sources: `postgresql`, `postgres`
  - ports: `5432`
  - `policy_tags.lockout_risk: medium`
  - `policy_tags.auth_family: password`
  - `policy_tags.transport: tcp`
  - `dictionary.allow_empty_username: false`
  - `dictionary.allow_empty_password: false`
  - `dictionary.expansion_profile: static_basic`
  - `results.credential_success_type: credential_valid`
  - `results.evidence_profile: postgresql_basic`

- `smtp.yaml`
  - aliases: `smtps`
  - ports: `25`, `465`, `587`
  - dict source: `smtp`
  - `policy_tags.lockout_risk: medium`
  - `policy_tags.auth_family: password`
  - `policy_tags.transport: tcp`
  - `dictionary.allow_empty_username: false`
  - `dictionary.allow_empty_password: false`
  - `dictionary.expansion_profile: static_basic`
  - `results.credential_success_type: credential_valid`
  - `results.evidence_profile: smtp_basic`

- `amqp.yaml`
  - aliases: `amqps`
  - ports: `5672`, `5671`
  - dict source: `amqp`
  - `policy_tags.lockout_risk: medium`
  - `policy_tags.auth_family: password`
  - `policy_tags.transport: tcp`
  - `dictionary.allow_empty_username: false`
  - `dictionary.allow_empty_password: false`
  - `dictionary.expansion_profile: static_basic`
  - `results.credential_success_type: credential_valid`
  - `results.evidence_profile: amqp_basic`

- [ ] **Step 2: Keep the alias regression tests metadata-first**

Re-run and preserve the existing tests that already encode the historical alias contracts:

- `TestLookupProtocolSpecSupportsAliasesAndPortFallback`
- `TestLookupProtocolSpecIncludesPhaseTwoBatchACredentialProtocols`

Add a new focused batch-B metadata test if needed only for explicit metadata coverage, not to duplicate the existing alias matrix.

- [ ] **Step 3: Run the batch-B metadata slice**

Run:

```bash
go test ./pkg/secprobe/metadata ./pkg/secprobe -run 'TestLookupProtocolSpecSupportsAliasesAndPortFallback|TestLookupProtocolSpecIncludesPhaseTwoBatchACredentialProtocols|TestLoadSpecsIncludesAllBuiltinProtocolNamesAfterPhase2' -v
```

Expected: PASS for the alias and port-fallback coverage that batch B owns. `TestLoadSpecsIncludesAllBuiltinProtocolNamesAfterPhase2` is intentionally not part of this batch gate because it remains a final phase-wide assertion.

- [ ] **Step 4: Commit batch-B metadata**

```bash
git add app/secprobe/protocols/postgresql.yaml app/secprobe/protocols/smtp.yaml app/secprobe/protocols/amqp.yaml pkg/secprobe/protocol_catalog_test.go
git commit -m "feat(secprobe): add phase-2 metadata batch b"
```

---

## Task 4: Add Batch C Metadata (`oracle`, `rdp`, `smb`, `vnc`, `snmp`)

**Files:**
- Create: `app/secprobe/protocols/oracle.yaml`
- Create: `app/secprobe/protocols/rdp.yaml`
- Create: `app/secprobe/protocols/smb.yaml`
- Create: `app/secprobe/protocols/vnc.yaml`
- Create: `app/secprobe/protocols/snmp.yaml`
- Modify: `pkg/secprobe/protocol_catalog_test.go`

- [ ] **Step 1: Preserve strict-port and alias semantics**

These files need extra care:

- `oracle.yaml`
  - alias: `oracle-tns`
  - strict port match remains `1521`
  - dict source: `oracle`
  - `policy_tags.lockout_risk: medium`
  - `policy_tags.auth_family: password`
  - `policy_tags.transport: tcp`
  - `dictionary.allow_empty_username: false`
  - `dictionary.allow_empty_password: false`
  - `dictionary.expansion_profile: static_basic`
  - `results.credential_success_type: credential_valid`
  - `results.evidence_profile: oracle_basic`

- `snmp.yaml`
  - strict port match remains `161`
  - dict source: `snmp`
  - `credential` capability only for now
  - `policy_tags.lockout_risk: low`
  - `policy_tags.auth_family: community`
  - `policy_tags.transport: udp`
  - `dictionary.allow_empty_username: true`
  - `dictionary.allow_empty_password: false`
  - `dictionary.expansion_profile: static_basic`
  - `results.credential_success_type: credential_valid`
  - `results.evidence_profile: snmp_basic`

- `smb.yaml`
  - alias: `cifs`
  - ports: `445`, `139`
  - dict source: `smb`
  - `policy_tags.lockout_risk: high`
  - `policy_tags.auth_family: password`
  - `policy_tags.transport: tcp`
  - `dictionary.allow_empty_username: false`
  - `dictionary.allow_empty_password: false`
  - `dictionary.expansion_profile: static_basic`
  - `results.credential_success_type: credential_valid`
  - `results.evidence_profile: smb_basic`

- `rdp.yaml`
  - port: `3389`
  - `policy_tags.lockout_risk: medium`
  - `policy_tags.auth_family: password`
  - `policy_tags.transport: tcp`
  - `dictionary.allow_empty_username: false`
  - `dictionary.allow_empty_password: false`
  - `dictionary.expansion_profile: static_basic`
  - `results.credential_success_type: credential_valid`
  - `results.evidence_profile: rdp_basic`

- `vnc.yaml`
  - port: `5900`
  - `policy_tags.lockout_risk: low`
  - `policy_tags.auth_family: password`
  - `policy_tags.transport: tcp`
  - `dictionary.allow_empty_username: true`
  - `dictionary.allow_empty_password: false`
  - `dictionary.expansion_profile: static_basic`
  - `results.credential_success_type: credential_valid`
  - `results.evidence_profile: vnc_basic`

- [ ] **Step 2: Keep the existing strict-port tests green**

Do not weaken:

- `TestLookupProtocolSpecRejectsStrictMetadataTokenMatchOnWrongPort`
- `TestLookupProtocolSpecIncludesPhaseOneCredentialProtocols`
- `TestLookupProtocolSpecIncludesPhaseTwoBatchBCredentialProtocols`

If `requiresStrictPortMatch` still exists after this task, it must continue to protect `oracle` and `snmp`.

- [ ] **Step 3: Run the batch-C metadata slice**

Run:

```bash
go test ./pkg/secprobe/metadata ./pkg/secprobe -run 'TestLookupProtocolSpecRejectsStrictMetadataTokenMatchOnWrongPort|TestLookupProtocolSpecIncludesPhaseOneCredentialProtocols|TestLookupProtocolSpecIncludesPhaseTwoBatchBCredentialProtocols|TestLoadSpecsIncludesAllBuiltinProtocolNamesAfterPhase2' -v
```

Expected: PASS for the strict-port and alias coverage that batch C owns. `TestLoadSpecsIncludesAllBuiltinProtocolNamesAfterPhase2` is intentionally not part of this batch gate because it remains a final phase-wide assertion.

- [ ] **Step 4: Commit batch-C metadata**

```bash
git add app/secprobe/protocols/oracle.yaml app/secprobe/protocols/rdp.yaml app/secprobe/protocols/smb.yaml app/secprobe/protocols/vnc.yaml app/secprobe/protocols/snmp.yaml pkg/secprobe/protocol_catalog_test.go
git commit -m "feat(secprobe): add phase-2 metadata batch c"
```

---

## Task 5: Add Batch D Metadata (`mongodb`, `memcached`, `zookeeper`)

**Files:**
- Create: `app/secprobe/protocols/mongodb.yaml`
- Create: `app/secprobe/protocols/memcached.yaml`
- Create: `app/secprobe/protocols/zookeeper.yaml`
- Modify: `pkg/secprobe/protocol_catalog_test.go`

- [ ] **Step 1: Create multi-capability and unauthorized-only metadata**

Carry forward the current public contract:

- `mongodb.yaml`
  - alias: `mongo`
  - ports: `27017`
  - dict sources: `mongodb`, `mongo`
  - capabilities: `credential`, `unauthorized`, `enrichment`
  - `policy_tags.lockout_risk: medium`
  - `policy_tags.auth_family: password`
  - `policy_tags.transport: tcp`
  - `dictionary.allow_empty_username: false`
  - `dictionary.allow_empty_password: false`
  - `dictionary.expansion_profile: static_basic`
  - `results.credential_success_type: credential_valid`
  - `results.unauthorized_success_type: unauthorized_access`
  - `results.evidence_profile: mongodb_basic`

- `memcached.yaml`
  - port: `11211`
  - capabilities: `unauthorized` only
  - `policy_tags.lockout_risk: low`
  - `policy_tags.auth_family: none`
  - `policy_tags.transport: tcp`
  - `dictionary.default_sources: []`
  - `dictionary.allow_empty_username: false`
  - `dictionary.allow_empty_password: false`
  - `dictionary.expansion_profile: none`
  - `results.unauthorized_success_type: unauthorized_access`
  - `results.evidence_profile: memcached_basic`

- `zookeeper.yaml`
  - port: `2181`
  - capabilities: `unauthorized` only
  - `policy_tags.lockout_risk: low`
  - `policy_tags.auth_family: none`
  - `policy_tags.transport: tcp`
  - `dictionary.default_sources: []`
  - `dictionary.allow_empty_username: false`
  - `dictionary.allow_empty_password: false`
  - `dictionary.expansion_profile: none`
  - `results.unauthorized_success_type: unauthorized_access`
  - `results.evidence_profile: zookeeper_basic`

- [ ] **Step 2: Keep unauthorized capability declarations intact**

Preserve these existing behaviors:

- `ProtocolSupportsKind("mongodb", ProbeKindCredential)` remains true
- `ProtocolSupportsKind("mongodb", ProbeKindUnauthorized)` remains true
- `ProtocolSupportsKind("memcached", ProbeKindCredential)` remains false
- `ProtocolSupportsKind("memcached", ProbeKindUnauthorized)` remains true
- `ProtocolSupportsKind("zookeeper", ProbeKindUnauthorized)` remains true

- [ ] **Step 3: Run the batch-D metadata slice**

Run:

```bash
go test ./pkg/secprobe/metadata ./pkg/secprobe -run 'TestLoadSpecsIncludesAllBuiltinProtocolNamesAfterPhase2|TestLookupProtocolSpecIncludesPhaseThreeUnauthorizedProtocols|TestLookupProtocolSpecSupportsMongoDBCredentialAndUnauthorized|TestProtocolSupportsKindUsesCatalogDeclaration' -v
```

Expected: PASS once the last three YAMLs land. This is the first batch where `TestLoadSpecsIncludesAllBuiltinProtocolNamesAfterPhase2` is expected to turn green because all planned metadata files now exist.

- [ ] **Step 4: Commit batch-D metadata**

```bash
git add app/secprobe/protocols/mongodb.yaml app/secprobe/protocols/memcached.yaml app/secprobe/protocols/zookeeper.yaml pkg/secprobe/protocol_catalog_test.go
git commit -m "feat(secprobe): add phase-2 metadata batch d"
```

---

## Task 6: Shrink the Legacy Catalog and Lock the Phase-2 Baseline

**Files:**
- Modify: `pkg/secprobe/protocol_catalog.go`
- Modify: `pkg/secprobe/assets_test.go`
- Modify: `pkg/secprobe/dictionaries_test.go`
- Modify: `pkg/secprobe/default_registry_test.go`
- Modify: `README.md`

- [ ] **Step 1: Reduce `legacyProtocolSpecs` to a narrow fallback set**

Once all batch YAML files exist and the tests are green:

- remove the migrated protocols from `legacyProtocolSpecs`
- keep only temporary fallback entries if one is still required for compatibility during later engine phases
- do **not** remove the legacy adapter path in this phase

The preferred end state for this task is:

```go
var legacyProtocolSpecs = []ProtocolSpec{}
```

If a non-empty fallback set is still needed, document exactly why in a code comment above the remaining entries.

- [ ] **Step 2: Lock the metadata-first baseline in regression tests**

Add or extend tests so the final phase-2 slice verifies:

- `LoadBuiltin()` includes every current builtin protocol
- `LookupProtocolSpec(...)` still matches all alias, port, and capability expectations
- `BuiltinCredentials(...)` still resolves the same dict-backed protocols
- default registry protocol presence remains unchanged

- [ ] **Step 3: Document the metadata coverage expansion**

Update `README.md` under the existing secprobe engine notes with a short factual addendum such as:

```md
- phase 2 将历史内置协议目录逐步迁移到 `app/secprobe/protocols/*.yaml`，保留既有 public API 与结果契约
```

- [ ] **Step 4: Run the full phase-2 regression slice**

Run:

```bash
go test ./app ./pkg/secprobe -v
```

Expected: PASS with metadata loader, catalog, dictionary, assets, scan, and registry tests all green.

- [ ] **Step 5: Commit the phase-2 metadata migration**

```bash
git add app/secprobe/protocols pkg/secprobe/protocol_catalog.go pkg/secprobe/metadata/loader_test.go pkg/secprobe/protocol_catalog_test.go pkg/secprobe/assets_test.go pkg/secprobe/dictionaries_test.go pkg/secprobe/default_registry_test.go README.md
git commit -m "feat(secprobe): migrate builtin protocol catalog metadata"
```

---

## Self-Review Checklist

### Spec coverage

- YAML remains declarative; no execution logic, retry policy, or flow control is added.
- `LookupProtocolSpec` keeps the same public behavior while switching data sources.
- Alias-heavy protocols (`postgresql`, `smtp`, `amqp`, `oracle`, `smb`, `mongodb`) remain covered.
- Strict-port protocols (`oracle`, `snmp`) remain guarded.
- Unauthorized-only protocols (`memcached`, `zookeeper`) do not accidentally gain credential capability.

### Placeholder scan

- Every batch has explicit files, tests, and a verification command.
- No step requires removing the legacy adapter path yet.
- No step introduces new protocols outside the existing built-in set.

### Type consistency

- Metadata type names remain `Spec`, `Capabilities`, `PolicyTags`, `Dictionary`, `ResultProfile`.
- Public catalog type remains `ProtocolSpec`.
- `ProbeKindCredential` / `ProbeKindUnauthorized` stay the externally visible capability surface.

---

## Follow-up Plans

After this phase lands, write follow-up plans for:

1. Migrating the remaining credential protocols to atomic plugins
2. Adding the simple unauthorized template executor
3. Removing the legacy adapter path and any remaining legacy catalog fallback
