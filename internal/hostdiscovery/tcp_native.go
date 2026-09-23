package hostdiscovery

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

const maxNativeTCPInflight = 8

var readTCPRandom = rand.Read

var errNativeNoSignal = errors.New("native probe produced no host signal")

type nativeTCPInbound struct {
	sourceIP net.IP
	targetIP net.IP
	fragment bool
	response tcpResponse
}

type nativeTCPSession interface {
	LocalIP() net.IP
	LocalPort() uint16
	Send(tcpProbe) error
	Receive(time.Time) (nativeTCPInbound, error)
	SendReset(tcpProbe, tcpResponse, time.Time) error
	Close() error
}

type nativeTCPOpener func(context.Context, net.IP, time.Duration) (nativeTCPSession, error)

type nativeTCPRunner struct {
	mode   string
	opts   Options
	opener nativeTCPOpener
	now    func() time.Time
}

func newNativeTCPRunner(mode string, opts Options, opener nativeTCPOpener) Runner {
	return &nativeTCPRunner{mode: mode, opts: opts, opener: opener, now: time.Now}
}

// Run keeps one raw receive session and limits each round to eight outstanding
// ports. Every port gets a timeout beginning only after its packet is sent.
func (r *nativeTCPRunner) Run(ctx context.Context, target string) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	targetIP := net.ParseIP(target)
	if targetIP == nil {
		return Result{}, fmt.Errorf("%w: invalid TCP discovery target %q", ErrInvalidOptions, target)
	}
	if targetIP.To4() == nil {
		return Result{}, fmt.Errorf("%w: mode %s supports IPv4 only", ErrModeUnavailable, r.mode)
	}
	ports := uniqueValidPorts(r.opts.Ports)
	if len(ports) == 0 {
		return Result{}, fmt.Errorf("%w: mode %s requires a valid TCP port", ErrInvalidOptions, r.mode)
	}
	timeout := r.opts.Timeout
	if timeout <= 0 {
		timeout = time.Second
	}
	session, err := r.opener(ctx, targetIP.To4(), timeout)
	if err != nil {
		if errors.Is(err, errNativeNoSignal) {
			return Result{}, nil
		}
		return Result{}, err
	}
	defer session.Close()
	closeDone := make(chan struct{})
	stopClose := context.AfterFunc(ctx, func() {
		defer close(closeDone)
		_ = session.Close()
	})
	defer func() {
		if !stopClose() {
			<-closeDone
		}
	}()

	inflight := make(map[uint16]tcpProbe, maxNativeTCPInflight)
	nextPort := 0
	sent := 0
	normalNoSignal := false
	var issues []error
	probeFailed := false

	dispatch := func() {
		for len(inflight) < maxNativeTCPInflight && nextPort < len(ports) {
			port := uint16(ports[nextPort])
			nextPort++
			probe, tokenErr := r.newProbe(port)
			if tokenErr != nil {
				probeFailed = true
				issues = append(issues, tokenErr)
				continue
			}
			if ctx.Err() != nil {
				return
			}
			if sendErr := session.Send(probe); sendErr != nil {
				wrapped := classifyNativeTCPError("send", sendErr)
				if errors.Is(wrapped, errNativeNoSignal) {
					normalNoSignal = true
					continue
				}
				if errors.Is(wrapped, ErrProbeFailed) {
					probeFailed = true
				}
				issues = append(issues, fmt.Errorf("port %d: %w", port, wrapped))
				continue
			}
			probe.deadline = r.now().Add(timeout)
			inflight[port] = probe
			sent++
		}
	}

	for {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		dispatch()
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if len(inflight) == 0 {
			if nextPort < len(ports) {
				continue
			}
			if sent > 0 || normalNoSignal {
				return Result{}, nil
			}
			if probeFailed {
				return Result{}, errors.Join(issues...)
			}
			return Result{}, errors.Join(issues...)
		}

		deadline := earliestTCPDeadline(inflight)
		inbound, receiveErr := session.Receive(deadline)
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		now := r.now()
		for port, probe := range inflight {
			if !now.Before(probe.deadline) {
				delete(inflight, port)
			}
		}
		if receiveErr != nil {
			if isNetworkTimeout(receiveErr) || errors.Is(receiveErr, errNativeNoSignal) {
				continue
			}
			classified := classifyNativeTCPError("receive", receiveErr)
			if errors.Is(classified, errNativeNoSignal) {
				continue
			}
			return Result{}, classified
		}
		if inbound.fragment || !inbound.sourceIP.Equal(targetIP) || !inbound.targetIP.Equal(session.LocalIP()) {
			continue
		}
		probe, ok := inflight[inbound.response.sourcePort]
		if !ok || !r.now().Before(probe.deadline) || !matchTCPProbeResponse(probe, inbound.response, session.LocalPort()) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if r.mode == "tcp-syn" && inbound.response.flags&(tcpFlagSYN|tcpFlagACK) == tcpFlagSYN|tcpFlagACK {
			cleanupDeadline := r.now().Add(minDuration(timeout, 100*time.Millisecond))
			_ = session.SendReset(probe, inbound.response, cleanupDeadline)
			if err := ctx.Err(); err != nil {
				return Result{}, err
			}
		}
		return Result{Matched: true, Method: r.mode}, nil
	}
}

func (r *nativeTCPRunner) newProbe(port uint16) (tcpProbe, error) {
	buffer := make([]byte, 8)
	if _, err := readTCPRandom(buffer); err != nil {
		return tcpProbe{}, fmt.Errorf("%w: mode %s random token: %w", ErrProbeFailed, r.mode, err)
	}
	probe := tcpProbe{
		mode:       r.mode,
		remotePort: port,
		seq:        binary.BigEndian.Uint32(buffer[0:4]),
		ack:        binary.BigEndian.Uint32(buffer[4:8]),
	}
	if probe.ack == 0 {
		probe.ack = 1
	}
	return probe, nil
}

func earliestTCPDeadline(inflight map[uint16]tcpProbe) time.Time {
	var earliest time.Time
	for _, probe := range inflight {
		if earliest.IsZero() || probe.deadline.Before(earliest) {
			earliest = probe.deadline
		}
	}
	return earliest
}

func uniqueValidPorts(ports []int) []int {
	seen := make(map[int]struct{}, len(ports))
	result := make([]int, 0, len(ports))
	for _, port := range validPorts(ports) {
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		result = append(result, port)
	}
	return result
}

func classifyNativeTCPError(operation string, err error) error {
	if isNativeCapabilityError(err) {
		return fmt.Errorf("%w: native TCP %s unavailable: %w", ErrModeUnavailable, operation, err)
	}
	// A send error means no probe was transmitted; receive errors can also
	// report a network response after a successful send.
	if operation == "send" && (errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH)) {
		return fmt.Errorf("%w: native TCP %s: %w", ErrProbeFailed, operation, err)
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return errNativeNoSignal
	}
	return fmt.Errorf("%w: native TCP %s: %w", ErrProbeFailed, operation, err)
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}
