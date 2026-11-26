package tcpservices

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yrighc/gomap/config/common"
)

func TestTLSReadWithProbeRetainsHandshakeOnReadTimeout(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	host, port := testEndpoint(t, server.URL)
	confirmed := false
	response, err := tlsReadWithProbe(host, "", port, make([]byte, 4096), 200*time.Millisecond, false, nil, func(subject, dns string) {
		confirmed = true
		if subject == "" {
			t.Error("handshake observer lost certificate subject")
		}
	})
	if !confirmed || response != "" {
		t.Fatalf("confirmed=%v response=%q err=%v", confirmed, response, err)
	}
	if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("expected application read timeout after a successful handshake, got %v", err)
	}
}

func TestTLSReadWithProbeDoesNotConfirmPlaintext(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	host, port := testEndpoint(t, server.URL)
	confirmed := false
	_, err := tlsReadWithProbe(host, "", port, make([]byte, 4096), time.Second, false, nil, func(string, string) {
		confirmed = true
	})
	if confirmed || err == nil {
		t.Fatalf("plaintext response must not confirm TLS: confirmed=%v err=%v", confirmed, err)
	}
}

func TestTcpPortServerWithoutTLSPortHints(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		name := "HTTP"
		if useTLS {
			name = "HTTPS"
		}
		t.Run(name, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("without-port-hints"))
			}))
			if useTLS {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			host, port := testEndpoint(t, server.URL)

			oldProbes, oldServices, oldSSL := common.NmapData, common.ServiceMap, common.SslPortsMap
			common.ServiceMap = map[int]map[string]string{}
			common.SslPortsMap = map[int]bool{}
			common.NmapData = common.Nmap{PortToProbes: map[int][]common.MapValue{
				port: {{Protocol: "TCP", ProbeBytes: `GET / HTTP/1.0\r\n\r\n`}},
			}}
			t.Cleanup(func() {
				common.NmapData, common.ServiceMap, common.SslPortsMap = oldProbes, oldServices, oldSSL
			})

			// The supplied connection is only for passive banner reading. An EOF
			// skips that wait; all active probes still use the real local server.
			passive, peer := net.Pipe()
			_ = peer.Close()
			defer passive.Close()
			banner, subject, _, service, _, _ := TcpPortServer(host, "", port, make([]byte, 4096), passive, false)
			want := "http"
			if useTLS {
				want = "https"
				if subject == "" {
					t.Fatal("missing TLS certificate")
				}
			}
			if service != want || !strings.Contains(banner, "without-port-hints") {
				t.Fatalf("service=%q banner=%q; want %q with real HTTP response", service, banner, want)
			}
		})
	}
}

func testEndpoint(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname(), port
}
