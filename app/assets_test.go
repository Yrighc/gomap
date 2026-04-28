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
		prefix   string
	}{
		{protocol: "ftp", prefix: "ftp : ftp\nftp : 123456\nadmin : admin\nanonymous : anonymous\n"},
		{protocol: "mssql", prefix: "sa : sa\nsa : 123456\nadmin : admin\nsa : P@ssw0rd\n"},
		{protocol: "mysql", prefix: "root : root\nroot : 123456\nmysql : mysql\nadmin : admin\n"},
		{protocol: "postgresql", prefix: "postgres : postgres\npostgres : 123456\nadmin : admin\ntest : test\n"},
		{protocol: "rdp", prefix: "administrator : administrator\nadministrator : 123456\nadmin : admin\ntest : test\n"},
		{protocol: "redis", prefix: "default : 123456\ndefault : redis\nredis : redis\nredis : {{key}}\n"},
		{protocol: "smb", prefix: "administrator : administrator\nadministrator : 123456\nguest : guest\nadmin : admin\n"},
		{protocol: "ssh", prefix: "root : root\nroot : 123456\nadmin : admin\ntest : test\n"},
		{protocol: "telnet", prefix: "admin : admin\nroot : root\nroot : 123456\nuser : user\n"},
		{protocol: "vnc", prefix: " : 123456\n : vnc\n : admin\n : password\n"},
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
			if !strings.HasPrefix(string(data), tt.prefix) {
				t.Fatalf("expected data to have prefix %q", tt.prefix)
			}
		})
	}
}
