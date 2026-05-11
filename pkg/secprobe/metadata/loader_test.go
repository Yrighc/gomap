package metadata

import (
	"maps"
	"slices"
	"testing"
)

func TestLoadSpecsIncludesRedisAndSSHAliases(t *testing.T) {
	specs, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin() error = %v", err)
	}

	redis, ok := specs["redis"]
	if !ok {
		keys := slices.Sorted(maps.Keys(specs))
		t.Fatalf("expected redis spec, got keys %v", keys)
	}
	if redis.PolicyTags.LockoutRisk != "low" {
		t.Fatalf("expected redis lockout risk low, got %+v", redis.PolicyTags)
	}
	if !slices.Equal(redis.Aliases, []string{"redis/ssl", "redis/tls"}) {
		t.Fatalf("expected redis aliases %v, got %v", []string{"redis/ssl", "redis/tls"}, redis.Aliases)
	}
	if !slices.Equal(redis.Ports, []int{6379}) {
		t.Fatalf("expected redis port 6379, got %v", redis.Ports)
	}

	ssh, ok := specs["ssh"]
	if !ok {
		keys := slices.Sorted(maps.Keys(specs))
		t.Fatalf("expected ssh spec, got keys %v", keys)
	}
	if len(ssh.Ports) != 1 || ssh.Ports[0] != 22 {
		t.Fatalf("expected ssh port 22, got %+v", ssh.Ports)
	}
	if len(ssh.Aliases) != 0 {
		t.Fatalf("expected ssh aliases empty, got %+v", ssh.Aliases)
	}
}

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

func TestLoadSpecsIncludesPhase2HistoricalContracts(t *testing.T) {
	specs, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin() error = %v", err)
	}

	ftp, ok := specs["ftp"]
	if !ok {
		t.Fatalf("expected ftp spec, got keys %v", slices.Sorted(maps.Keys(specs)))
	}
	if ftp.Name != "ftp" || !slices.Equal(ftp.Ports, []int{21}) {
		t.Fatalf("expected ftp metadata contract, got %+v", ftp)
	}

	mongodb, ok := specs["mongodb"]
	if !ok {
		t.Fatalf("expected mongodb spec, got keys %v", slices.Sorted(maps.Keys(specs)))
	}
	if !slices.Equal(mongodb.Aliases, []string{"mongo"}) {
		t.Fatalf("expected mongodb alias metadata, got %+v", mongodb)
	}
	if !mongodb.Capabilities.Unauthorized || !mongodb.Capabilities.Credential || !mongodb.Capabilities.Enrichment {
		t.Fatalf("expected mongodb capabilities in metadata, got %+v", mongodb.Capabilities)
	}
}

func TestLoadBuiltinKeepsUnauthorizedTemplateReferenceDeclarative(t *testing.T) {
	specs, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin() error = %v", err)
	}

	memcached, ok := specs["memcached"]
	if !ok {
		keys := slices.Sorted(maps.Keys(specs))
		t.Fatalf("expected memcached spec, got keys %v", keys)
	}
	if memcached.Templates.Unauthorized != "memcached" {
		t.Fatalf("expected memcached unauthorized template reference, got %+v", memcached.Templates)
	}
}

func TestLoadBuiltinNormalizesDictionaryDefaultTiers(t *testing.T) {
	specs, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin() error = %v", err)
	}

	ssh, ok := specs["ssh"]
	if !ok {
		t.Fatalf("expected ssh spec, got keys %v", slices.Sorted(maps.Keys(specs)))
	}

	if !slices.Equal(ssh.Dictionary.DefaultTiers, []string{"top", "common"}) {
		t.Fatalf("expected ssh default tiers [top common], got %v", ssh.Dictionary.DefaultTiers)
	}

	mysql, ok := specs["mysql"]
	if !ok {
		t.Fatalf("expected mysql spec, got keys %v", slices.Sorted(maps.Keys(specs)))
	}
	if !slices.Equal(mysql.Dictionary.DefaultTiers, []string{"top", "common"}) {
		t.Fatalf("expected mysql default tiers [top common], got %v", mysql.Dictionary.DefaultTiers)
	}

	redis, ok := specs["redis"]
	if !ok {
		t.Fatalf("expected redis spec, got keys %v", slices.Sorted(maps.Keys(specs)))
	}
	if !slices.Equal(redis.Dictionary.DefaultTiers, []string{"top", "common"}) {
		t.Fatalf("expected redis default tiers [top common], got %v", redis.Dictionary.DefaultTiers)
	}

	telnet, ok := specs["telnet"]
	if !ok {
		t.Fatalf("expected telnet spec, got keys %v", slices.Sorted(maps.Keys(specs)))
	}
	if !slices.Equal(telnet.Dictionary.DefaultTiers, []string{"top", "common"}) {
		t.Fatalf("expected telnet default tiers [top common], got %v", telnet.Dictionary.DefaultTiers)
	}
}

func TestLoadBuiltinUsesFscanExpandedProtocolUsers(t *testing.T) {
	specs, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin() error = %v", err)
	}

	tests := []struct {
		protocol string
		users    []string
	}{
		{protocol: "ftp", users: []string{"ftp", "admin", "www", "web", "root", "db", "wwwroot", "data"}},
		{protocol: "amqp", users: []string{"guest", "admin", "administrator", "rabbit", "rabbitmq", "root"}},
		{protocol: "elasticsearch", users: []string{"elastic", "admin", "kibana"}},
	}

	for _, tt := range tests {
		spec, ok := specs[tt.protocol]
		if !ok {
			t.Fatalf("expected %s spec, got keys %v", tt.protocol, slices.Sorted(maps.Keys(specs)))
		}
		if !slices.Equal(spec.Dictionary.DefaultUsers, tt.users) {
			t.Fatalf("%s default users = %v, want %v", tt.protocol, spec.Dictionary.DefaultUsers, tt.users)
		}
	}
}

func TestNormalizeSpecNormalizesDictionaryDefaultTiers(t *testing.T) {
	spec := normalizeSpec(Spec{
		Name: "ssh",
		Dictionary: Dictionary{
			DefaultTiers: []string{" Top ", "COMMON", "", "common"},
		},
	})

	if !slices.Equal(spec.Dictionary.DefaultTiers, []string{"top", "common", "common"}) {
		t.Fatalf("expected normalized default tiers, got %v", spec.Dictionary.DefaultTiers)
	}
}

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
				{Username: "", Password: "nopassuser"},
				{Username: "empty-pass", Password: ""},
			},
			DefaultTiers: []string{" Top ", "", "COMMON "},
		},
		Templates: TemplateRefs{
			Unauthorized: " Redis ",
		},
	})

	if spec.Name != "redis" {
		t.Fatalf("expected normalized name redis, got %q", spec.Name)
	}
	if !slices.Equal(spec.Aliases, []string{"redis/tls", "redis/ssl"}) {
		t.Fatalf("expected normalized aliases, got %v", spec.Aliases)
	}
	if !slices.Equal(spec.Dictionary.DefaultUsers, []string{"default", "", "root"}) {
		t.Fatalf("expected normalized default users, got %v", spec.Dictionary.DefaultUsers)
	}
	if spec.Dictionary.PasswordSource != "builtin:passwords/global" {
		t.Fatalf("expected normalized password source, got %q", spec.Dictionary.PasswordSource)
	}
	if !slices.Equal(spec.Dictionary.ExtraPasswords, []string{"Redis", "Default"}) {
		t.Fatalf("expected trimmed extra passwords preserving case, got %v", spec.Dictionary.ExtraPasswords)
	}
	wantPairs := []CredentialPair{
		{Username: "Scott", Password: "tiger"},
		{Username: "", Password: "nopassuser"},
		{Username: "empty-pass", Password: ""},
	}
	if !slices.Equal(spec.Dictionary.DefaultPairs, wantPairs) {
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

	if !slices.Equal(spec.Dictionary.DefaultUsers, []string{"", "", ""}) {
		t.Fatalf("expected explicit empty default users to stay declared, got %v", spec.Dictionary.DefaultUsers)
	}
	if spec.Dictionary.PasswordSource != "" {
		t.Fatalf("expected empty password source, got %q", spec.Dictionary.PasswordSource)
	}
	if spec.Dictionary.ExtraPasswords != nil {
		t.Fatalf("expected empty extra passwords to normalize to nil, got %v", spec.Dictionary.ExtraPasswords)
	}
	if !slices.Equal(spec.Dictionary.DefaultPairs, []CredentialPair{{Username: "", Password: "x"}, {Username: "root", Password: ""}}) {
		t.Fatalf("expected explicit empty default pairs to stay declared, got %+v", spec.Dictionary.DefaultPairs)
	}
	if spec.Dictionary.DefaultTiers != nil {
		t.Fatalf("expected empty default tiers to normalize to nil, got %v", spec.Dictionary.DefaultTiers)
	}
}
