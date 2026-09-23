package updservices

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/yrighc/gomap/config/common"
)

func replaceUDPAssets(t *testing.T, port int, rules []common.MapValue, service string) {
	t.Helper()
	originalData := common.NmapData
	originalServices := common.ServiceMap
	common.NmapData = common.Nmap{PortToProbes: map[int][]common.MapValue{port: rules}}
	common.ServiceMap = map[int]map[string]string{port: {"udp": service}}
	t.Cleanup(func() {
		common.NmapData = originalData
		common.ServiceMap = originalServices
	})
}

func replaceUDPDial(t *testing.T, dial func(context.Context, string, string) (net.Conn, error)) {
	t.Helper()
	original := dialUDPContext
	dialUDPContext = dial
	t.Cleanup(func() { dialUDPContext = original })
}

func udpRule(match *regexp2.Regexp) common.MapValue {
	return common.MapValue{Protocol: "UDP", ProbeBytes: "probe", Msg: []common.MatchRule{{
		Name: "demo", Regex: match, Service: "1.0",
	}}}
}

func TestProbePayloadPreservesMixedHexAndASCII(t *testing.T) {
	encoded := `0\x82\0/\x02\x01\0\x04\x06public\xa0\x82\0`
	want := []byte{0x30, 0x82, 0x00, 0x2f, 0x02, 0x01, 0x00, 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', 0xa0, 0x82, 0x00}

	got := probePayload(encoded)
	if string(got) != string(want) {
		t.Fatalf("mixed UDP probe payload changed: got=%x want=%x", got, want)
	}
}

func TestUcpPortServerDoesNotGuessServiceWithoutResponse(t *testing.T) {
	const port = 53001
	replaceUDPAssets(t, port, []common.MapValue{udpRule(nil)}, "domain")
	replaceUDPDial(t, func(context.Context, string, string) (net.Conn, error) {
		return &stubUDPConn{readErr: errors.New("timeout")}, nil
	})

	result := UcpPortServer(context.Background(), "192.0.2.1", port, time.Second)
	if result.Responded || result.Service != "" || result.Banner != "" {
		t.Fatalf("service table or successful write made a port look open: %#v", result)
	}
}

func TestUcpPortServerDoesNotDialWhenPortHasNoUDPProbe(t *testing.T) {
	const port = 53002
	replaceUDPAssets(t, port, nil, "domain")
	var dials atomic.Int32
	replaceUDPDial(t, func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return &stubUDPConn{}, nil
	})

	result := UcpPortServer(context.Background(), "192.0.2.1", port, time.Second)
	if result.Responded || result.Service != "" {
		t.Fatalf("port without probe unexpectedly produced a result: %#v", result)
	}
	if got := dials.Load(); got != 0 {
		t.Fatalf("port without UDP probe dialed %d times", got)
	}
}

func TestUcpPortServerRecordsDatagramResponses(t *testing.T) {
	tests := []struct {
		name        string
		response    []byte
		match       *regexp2.Regexp
		wantBanner  string
		wantService string
	}{
		{name: "matched non-empty", response: []byte("pong"), match: regexp2.MustCompile("pong", 0), wantBanner: "pong", wantService: "demo"},
		{name: "legal zero length", response: []byte{}, wantService: "domain?"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := startUDPResponder(t, tt.response)
			port := server.LocalAddr().(*net.UDPAddr).Port
			replaceUDPAssets(t, port, []common.MapValue{udpRule(tt.match)}, "domain")

			result := UcpPortServer(context.Background(), "127.0.0.1", port, time.Second)
			if !result.Responded || result.Banner != tt.wantBanner || result.Service != tt.wantService {
				t.Fatalf("unexpected datagram result: %#v", result)
			}
		})
	}
}

func TestUcpPortServerFailuresWithoutDataDoNotRespond(t *testing.T) {
	const port = 53003
	for _, test := range []struct {
		name    string
		dialErr error
		conn    *stubUDPConn
	}{
		{name: "dial", dialErr: errors.New("dial")},
		{name: "deadline", conn: &stubUDPConn{deadErr: errors.New("deadline")}},
		{name: "write", conn: &stubUDPConn{writeErr: errors.New("write")}},
		{name: "read", conn: &stubUDPConn{readErr: errors.New("read")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			replaceUDPAssets(t, port, []common.MapValue{udpRule(nil)}, "domain")
			replaceUDPDial(t, func(context.Context, string, string) (net.Conn, error) {
				return test.conn, test.dialErr
			})
			result := UcpPortServer(context.Background(), "192.0.2.1", port, time.Second)
			if result.Responded || result.Service != "" {
				t.Fatalf("%s failure without data became an open result: %#v", test.name, result)
			}
			if test.conn != nil && !test.conn.closed.Load() {
				t.Fatalf("%s failure leaked its UDP connection", test.name)
			}
		})
	}
}

func TestUcpPortServerPreservesDataReceivedWithReadError(t *testing.T) {
	const port = 53007
	replaceUDPAssets(t, port, []common.MapValue{udpRule(nil)}, "")
	replaceUDPDial(t, func(context.Context, string, string) (net.Conn, error) {
		return &stubUDPConn{readData: []byte("partial"), readErr: errors.New("late read error")}, nil
	})

	result := UcpPortServer(context.Background(), "192.0.2.1", port, time.Second)
	if !result.Responded || result.Banner != "partial" {
		t.Fatalf("received bytes were discarded after read error: %#v", result)
	}
}

func TestUcpPortServerKeepsEarlierResponseAfterLaterFailure(t *testing.T) {
	const port = 53008
	replaceUDPAssets(t, port, []common.MapValue{udpRule(nil), udpRule(nil)}, "domain")
	var call atomic.Int32
	replaceUDPDial(t, func(context.Context, string, string) (net.Conn, error) {
		if call.Add(1) == 1 {
			return &stubUDPConn{readData: []byte("first")}, nil
		}
		return &stubUDPConn{readErr: errors.New("timeout")}, nil
	})

	result := UcpPortServer(context.Background(), "192.0.2.1", port, time.Second)
	if !result.Responded || result.Banner != "first" || result.Service != "domain?" {
		t.Fatalf("later failure erased response evidence: %#v", result)
	}
}

func TestUcpPortServerUsesCallerTimeoutForEachProbe(t *testing.T) {
	const port = 53009
	replaceUDPAssets(t, port, []common.MapValue{udpRule(nil)}, "")
	const timeout = 50 * time.Millisecond
	started := time.Now()
	replaceUDPDial(t, func(ctx context.Context, _, _ string) (net.Conn, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("UDP dial context has no deadline")
		}
		if remaining := deadline.Sub(started); remaining <= 0 || remaining > 2*timeout {
			t.Fatalf("UDP dial deadline does not use caller timeout: %s", remaining)
		}
		return &stubUDPConn{readErr: errors.New("timeout")}, nil
	})

	result := UcpPortServer(context.Background(), "192.0.2.1", port, timeout)
	if result.Responded {
		t.Fatalf("timeout probe unexpectedly responded: %#v", result)
	}
}

func TestUcpPortServerTimeoutThenNextProbeUsesFreshConnection(t *testing.T) {
	const port = 53010
	replaceUDPAssets(t, port, []common.MapValue{udpRule(nil), udpRule(nil)}, "")
	first := &stubUDPConn{readErr: errors.New("timeout")}
	second := &stubUDPConn{readData: []byte("second")}
	var dials atomic.Int32
	replaceUDPDial(t, func(context.Context, string, string) (net.Conn, error) {
		if dials.Add(1) == 1 {
			return first, nil
		}
		return second, nil
	})

	result := UcpPortServer(context.Background(), "192.0.2.1", port, time.Second)
	if !result.Responded || result.Banner != "second" {
		t.Fatalf("second probe response was lost after first timeout: %#v", result)
	}
	if !first.closed.Load() || !second.closed.Load() {
		t.Fatalf("UDP probe connections were not individually released: first=%v second=%v", first.closed.Load(), second.closed.Load())
	}
}

func TestUcpPortServerCancellationPreventsDialAndClosesRead(t *testing.T) {
	t.Run("before dial", func(t *testing.T) {
		const port = 53004
		replaceUDPAssets(t, port, []common.MapValue{udpRule(nil)}, "")
		var dials atomic.Int32
		replaceUDPDial(t, func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return &stubUDPConn{}, nil
		})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if result := UcpPortServer(ctx, "192.0.2.1", port, time.Second); result.Responded {
			t.Fatalf("canceled probe responded: %#v", result)
		}
		if got := dials.Load(); got != 0 {
			t.Fatalf("canceled probe dialed %d times", got)
		}
	})

	t.Run("during read prevents next probe", func(t *testing.T) {
		const port = 53005
		replaceUDPAssets(t, port, []common.MapValue{udpRule(nil), udpRule(nil)}, "")
		conn := newBlockingUDPConn()
		var dials atomic.Int32
		replaceUDPDial(t, func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return conn, nil
		})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan ProbeResult, 1)
		go func() { done <- UcpPortServer(ctx, "192.0.2.1", port, time.Second) }()
		<-conn.wrote
		cancel()
		select {
		case result := <-done:
			if result.Responded || !conn.wasClosed() {
				t.Fatalf("cancellation did not release blocked UDP read: result=%#v closed=%v", result, conn.wasClosed())
			}
			if got := dials.Load(); got != 1 {
				t.Fatalf("cancellation started %d UDP probes; expected only the active probe", got)
			}
		case <-time.After(time.Second):
			t.Fatal("cancellation did not return from UDP read")
		}
	})
}

func startUDPResponder(t *testing.T, response []byte) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 128)
		n, peer, err := conn.ReadFromUDP(buf)
		if err == nil && n >= 0 {
			_, _ = conn.WriteToUDP(response, peer)
		}
	}()
	t.Cleanup(func() {
		_ = conn.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("UDP responder did not exit")
		}
	})
	return conn
}

type stubUDPConn struct {
	readData []byte
	readErr  error
	writeErr error
	deadErr  error
	closed   atomic.Bool
}

func (c *stubUDPConn) Read(p []byte) (int, error) {
	if c.readData != nil {
		return copy(p, c.readData), c.readErr
	}
	return 0, c.readErr
}
func (c *stubUDPConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(p), nil
}
func (c *stubUDPConn) Close() error                     { c.closed.Store(true); return nil }
func (c *stubUDPConn) LocalAddr() net.Addr              { return stubUDPAddr("local") }
func (c *stubUDPConn) RemoteAddr() net.Addr             { return stubUDPAddr("remote") }
func (c *stubUDPConn) SetDeadline(time.Time) error      { return c.deadErr }
func (c *stubUDPConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stubUDPConn) SetWriteDeadline(time.Time) error { return nil }

type blockingUDPConn struct {
	stubUDPConn
	wrote     chan struct{}
	closedCh  chan struct{}
	closeOnce sync.Once
}

func newBlockingUDPConn() *blockingUDPConn {
	return &blockingUDPConn{wrote: make(chan struct{}), closedCh: make(chan struct{})}
}
func (c *blockingUDPConn) Write(p []byte) (int, error) {
	select {
	case <-c.wrote:
	default:
		close(c.wrote)
	}
	return len(p), nil
}
func (c *blockingUDPConn) Read([]byte) (int, error) {
	<-c.closedCh
	return 0, net.ErrClosed
}
func (c *blockingUDPConn) Close() error {
	c.closeOnce.Do(func() {
		c.stubUDPConn.closed.Store(true)
		close(c.closedCh)
	})
	return nil
}
func (c *blockingUDPConn) wasClosed() bool { return c.stubUDPConn.closed.Load() }

type stubUDPAddr string

func (a stubUDPAddr) Network() string { return "udp" }
func (a stubUDPAddr) String() string  { return string(a) }
