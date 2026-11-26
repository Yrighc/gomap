package assetprobe

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestScanTransportEvidenceOn8765(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tls    bool
		silent bool
	}{
		{name: "unidentified_plaintext"},
		{name: "unidentified_TLS", tls: true},
		{name: "silent_TLS", tls: true, silent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			startUnidentifiedTransportServer(t, tc.tls, tc.silent)
			scanner, err := NewScanner(Options{Timeout: time.Second, DisableWeakPassword: true})
			if err != nil {
				t.Fatal(err)
			}
			result, err := scanner.Scan(context.Background(), ScanRequest{
				Target: "127.0.0.1", Ports: []int{8765}, Protocol: ProtocolTCP,
				HostDiscovery: HostDiscoveryOptions{Disabled: true},
			})
			if err != nil || len(result.Ports) != 1 {
				t.Fatalf("scan result=%#v err=%v", result, err)
			}
			port := result.Ports[0]
			if tc.tls {
				if port.Service != "unknown/ssl" || port.Subject == "" {
					t.Fatalf("must retain confirmed TLS without guessing an application: %#v", port)
				}
			} else if strings.Contains(port.Service, "ssl") || port.Service == "https" || port.Subject != "" {
				t.Fatalf("must not infer TLS from the service table: %#v", port)
			}
		})
	}
}

// All connections are local, and cleanup closes even those held by the
// scanner's existing budgeted background detection goroutine.
func startUnidentifiedTransportServer(t *testing.T, useTLS, silent bool) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:8765")
	if err != nil {
		t.Fatal(err)
	}
	if useTLS {
		certServer := httptest.NewTLSServer(http.NotFoundHandler())
		config := certServer.TLS.Clone()
		certServer.Close()
		listener = tls.NewListener(listener, config)
	}
	stop := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				closed := make(chan struct{})
				defer close(closed)
				go func() {
					select {
					case <-stop:
						_ = conn.Close()
					case <-closed:
					}
				}()
				if tlsConn, ok := conn.(*tls.Conn); ok {
					if err := tlsConn.Handshake(); err != nil {
						return
					}
				}
				if silent {
					_, _ = io.Copy(io.Discard, conn)
				} else {
					_, _ = io.WriteString(conn, "unidentified-transport-response\r\n")
				}
			}()
		}
	}()
	t.Cleanup(func() {
		close(stop)
		_ = listener.Close()
		workers.Wait()
	})
}

// Use the real rules and SDK output path: 8765 has a non-HTTPS service-table
// name and is not in the preferred Web-port list. Do not substitute a random
// port, which could miss the service-table fallback that caused the bug.
func TestScanHTTPTransportOn8765(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		name := "HTTP"
		if useTLS {
			name = "HTTPS"
		}
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:8765")
			if err != nil {
				t.Fatalf("regression test requires local port 8765: %v", err)
			}
			requests := make(chan string, 16)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case requests <- r.Method:
				default:
				}
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte("transport-regression"))
			}))
			_ = server.Listener.Close()
			server.Listener = listener
			if useTLS {
				server.StartTLS()
			} else {
				server.Start()
			}
			t.Cleanup(server.Close)

			scanner, err := NewScanner(Options{Timeout: time.Second, DisableWeakPassword: true})
			if err != nil {
				t.Fatal(err)
			}
			result, err := scanner.Scan(context.Background(), ScanRequest{
				Target: "127.0.0.1", Ports: []int{8765}, Protocol: ProtocolTCP,
				HostDiscovery: HostDiscoveryOptions{Disabled: true},
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Ports) != 1 {
				t.Fatalf("expected one open port, got %#v", result)
			}
			port := result.Ports[0]
			if !port.Open || (!useTLS && port.Service != "http") || (useTLS && port.Service != "https" && port.Service != "http/ssl") {
				t.Fatalf("wrong HTTP transport classification: %#v", port)
			}
			if !strings.HasPrefix(port.Banner, "HTTP/") || !strings.Contains(port.Banner, "transport-regression") {
				t.Fatalf("expected real HTTP response, got %q", port.Banner)
			}
			if useTLS && port.Subject == "" {
				t.Fatal("confirmed HTTPS must retain certificate subject")
			}
			select {
			case method := <-requests:
				if method != http.MethodGet {
					t.Fatalf("expected GET, got %q", method)
				}
			default:
				t.Fatal("scanner returned without sending an HTTP request")
			}
		})
	}
}
