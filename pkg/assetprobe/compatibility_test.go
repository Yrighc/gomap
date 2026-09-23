package assetprobe_test

import (
	"encoding/json"
	"testing"

	"github.com/yrighc/gomap/pkg/assetprobe"
)

// These fixed external-package samples guard the pre-existing public JSON
// contracts. They intentionally do not derive expectations from runtime data.
func TestLegacyPublicJSONShapes(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{
			name: "scan request",
			value: assetprobe.ScanRequest{
				Target:                    "example.test",
				Ports:                     []int{53},
				Protocol:                  assetprobe.ProtocolUDP,
				PortConcurrency:           2,
				PortRateLimit:             3,
				DisableServiceFingerprint: true,
				HostDiscovery:             assetprobe.HostDiscoveryOptions{Disabled: true},
			},
			want: `{"Target":"example.test","Ports":[53],"PortSpec":"","Protocol":"udp","PortConcurrency":2,"PortRateLimit":3,"Timeout":0,"MaxFingerprintPorts":0,"DisableServiceFingerprint":true,"HoneypotOpenThreshold":0,"HoneypotOpenRatio":0,"HostDiscovery":{"Disabled":true,"Modes":null,"Timeout":0,"Retries":0,"Ports":null}}`,
		},
		{
			name: "scan result and port",
			value: assetprobe.ScanResult{
				Target:     "example.test",
				ResolvedIP: "192.0.2.1",
				Protocol:   assetprobe.ProtocolUDP,
				Meta: assetprobe.ScanMeta{
					OpenPorts:               1,
					FingerprintedOpenPorts:  0,
					SkippedFingerprintPorts: 0,
					SuspectedHoneypot:       false,
					HoneypotReason:          "",
				},
				Ports: []assetprobe.PortResult{{
					Port:     53,
					Open:     true,
					Service:  "domain",
					Version:  "1",
					Banner:   "reply",
					Subject:  "",
					DNSNames: []string{"ns.example.test"},
				}},
			},
			want: `{"Target":"example.test","ResolvedIP":"192.0.2.1","Protocol":"udp","Meta":{"OpenPorts":1,"FingerprintedOpenPorts":0,"SkippedFingerprintPorts":0,"SuspectedHoneypot":false,"HoneypotReason":""},"Ports":[{"Port":53,"Open":true,"Service":"domain","Version":"1","Banner":"reply","Subject":"","DNSNames":["ns.example.test"]}]}`,
		},
		{
			name: "batch result",
			value: assetprobe.BatchScanResult{Results: []assetprobe.TargetScanResult{{
				Target: "example.test",
				Result: &assetprobe.ScanResult{
					Target:     "example.test",
					ResolvedIP: "192.0.2.1",
					Protocol:   assetprobe.ProtocolTCP,
				},
				Error: "",
			}}},
			want: `{"Results":[{"Target":"example.test","Result":{"Target":"example.test","ResolvedIP":"192.0.2.1","Protocol":"tcp","Meta":{"OpenPorts":0,"FingerprintedOpenPorts":0,"SkippedFingerprintPorts":0,"SuspectedHoneypot":false,"HoneypotReason":""},"Ports":null},"Error":""}]}`,
		},
		{
			name: "homepage result",
			value: assetprobe.HomepageResult{
				URL:         "https://example.test/",
				Title:       "Example",
				HTMLHash:    "html-hash",
				FaviconHash: "favicon-hash",
				ICP:         "",
				Response: assetprobe.HomepageResponse{
					HeaderMap: "Server: test",
					Header: assetprobe.HomepageResponseHeader{
						StatusCode:    200,
						ContentLength: 2,
						ContentType:   "text/plain",
						Server:        "test",
						RedirectChain: []string{"https://example.test/"},
					},
					Body: "ok",
				},
			},
			want: `{"URL":"https://example.test/","Title":"Example","HTMLHash":"html-hash","FaviconHash":"favicon-hash","ICP":"","Response":{"HeaderMap":"Server: test","Header":{"StatusCode":200,"ContentLength":2,"ContentType":"text/plain","Server":"test","RedirectChain":["https://example.test/"]},"Body":"ok"}}`,
		},
		{
			name: "scan event",
			value: assetprobe.ScanEvent{
				Kind:       assetprobe.ScanEventServiceMatch,
				Target:     "example.test",
				ResolvedIP: "192.0.2.1",
				Protocol:   assetprobe.ProtocolTCP,
				Port:       443,
				Service:    "https",
				Version:    "1",
				Method:     "",
			},
			want: `{"Kind":"service_match","Target":"example.test","ResolvedIP":"192.0.2.1","Protocol":"tcp","Port":443,"Service":"https","Version":"1","Method":"","Summary":null}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.value)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Fatalf("public JSON changed:\nwant: %s\n got: %s", tt.want, got)
			}
		})
	}
}
