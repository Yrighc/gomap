package appassets

import (
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

func TestEmbeddedSecprobeDictResourcesLoad(t *testing.T) {
	tests := []struct {
		protocol string
		snippets []string
	}{
		{protocol: "smtp", snippets: []string{"admin : 123456", "postmaster : postmaster"}},
		{protocol: "amqp", snippets: []string{"guest : guest", "rabbitmq : rabbitmq"}},
		{protocol: "ftp", snippets: []string{"ftp : 123456", "anonymous : anonymous"}},
		{protocol: "mssql", snippets: []string{"sa : 123456", "sa : P@ssw0rd"}},
		{protocol: "mysql", snippets: []string{"root : 123456", "mysql : mysql"}},
		{protocol: "postgresql", snippets: []string{"postgres : 123456", "test : test"}},
		{protocol: "rdp", snippets: []string{"administrator : 123456", "admin : admin"}},
		{protocol: "redis", snippets: []string{"default : redis", "redis : {{key}}"}},
		{protocol: "smb", snippets: []string{"administrator : 123456", "guest : guest"}},
		{protocol: "ssh", snippets: []string{"root : 123456", "admin : admin"}},
		{protocol: "telnet", snippets: []string{"admin : admin", "user : user"}},
		{protocol: "vnc", snippets: []string{" : 123456", " : password"}},
		{protocol: "oracle", snippets: []string{"sys : oracle", "system : manager"}},
		{protocol: "snmp", snippets: []string{" : public", " : private"}},
	}

	for _, tt := range tests {
		t.Run(tt.protocol, func(t *testing.T) {
			data, err := SecprobeDict(tt.protocol)
			if err != nil {
				t.Fatalf("load failed: %v", err)
			}
			if len(data) == 0 {
				t.Fatal("expected non-empty data")
			}
			for _, snippet := range tt.snippets {
				if !strings.Contains(string(data), snippet) {
					t.Fatalf("expected data to contain %q", snippet)
				}
			}
		})
	}
}
