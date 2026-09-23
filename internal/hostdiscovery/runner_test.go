package hostdiscovery

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func replaceModeFactories(t *testing.T, factories map[string]func(Options) Runner) {
	t.Helper()
	originalFactories := modeFactories
	modeFactories = factories
	t.Cleanup(func() { modeFactories = originalFactories })
}

func runLinuxAutomatic(ctx context.Context, ip string, opts Options) (Result, error) {
	normalized, err := validateOptions(ip, opts)
	if err != nil {
		return Result{}, err
	}
	return runAutomaticForPlatform(ctx, ip, normalized, "linux")
}

func TestAutomaticPlanIsPlatformAndFamilySpecific(t *testing.T) {
	if got := automaticPlanFor("linux", "2001:db8::1"); got.arp || !got.icmp || got.syn || !got.connect {
		t.Fatalf("unexpected Linux IPv6 plan: %#v", got)
	}
	if got := automaticPlanFor("linux", "192.0.2.1"); !got.arp || !got.icmp || !got.syn || !got.connect {
		t.Fatalf("unexpected Linux IPv4 plan: %#v", got)
	}
	if got := automaticPlanFor("darwin", "192.0.2.1"); got.arp || !got.icmp || got.syn || !got.connect {
		t.Fatalf("unexpected Darwin plan: %#v", got)
	}
	if got := automaticPlanFor("windows", "192.0.2.1"); got.arp || got.icmp || got.syn || !got.connect {
		t.Fatalf("unexpected Windows plan: %#v", got)
	}
}

func TestRunAutomaticARPMatchSkipsIPProbes(t *testing.T) {
	var icmpCalls, synCalls, connectCalls, ackCalls int
	replaceModeFactories(t, map[string]func(Options) Runner{
		"arp": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				return Result{Matched: true, Method: "arp"}, nil
			})
		},
		"icmp-echo": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { icmpCalls++; return Result{}, nil })
		},
		"tcp-syn": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { synCalls++; return Result{}, nil })
		},
		"tcp-connect": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { connectCalls++; return Result{}, nil })
		},
		"tcp-ack": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { ackCalls++; return Result{}, nil })
		},
	})

	result, err := runLinuxAutomatic(context.Background(), "127.0.0.1", Options{Ports: []int{80}})
	if err != nil || !result.Matched || result.Method != "arp" {
		t.Fatalf("unexpected automatic result: %+v, %v", result, err)
	}
	if icmpCalls != 0 || synCalls != 0 || connectCalls != 0 || ackCalls != 0 {
		t.Fatalf("ARP match started IP probes: icmp=%d syn=%d connect=%d ack=%d", icmpCalls, synCalls, connectCalls, ackCalls)
	}
}

func TestRunAutomaticARPOnlyRetriesNoSignal(t *testing.T) {
	var arpCalls, ipCalls int
	replaceModeFactories(t, map[string]func(Options) Runner{
		"arp": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { arpCalls++; return Result{}, nil })
		},
		"icmp-echo": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { ipCalls++; return Result{}, nil })
		},
		"tcp-syn": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { ipCalls++; return Result{}, nil })
		},
		"tcp-connect": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { ipCalls++; return Result{}, nil })
		},
		"tcp-ack": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { ipCalls++; return Result{}, nil })
		},
	})

	result, err := runLinuxAutomatic(context.Background(), "127.0.0.1", Options{Ports: []int{80}, Retries: 2})
	if err != nil || result.Matched {
		t.Fatalf("unexpected automatic result: %+v, %v", result, err)
	}
	if arpCalls != 2 || ipCalls != 0 {
		t.Fatalf("expected two ARP-only rounds, got arp=%d ip=%d", arpCalls, ipCalls)
	}
}

func TestRunAutomaticSYNUnavailableFallsBackToConnect(t *testing.T) {
	var synCalls, connectCalls, ackCalls int
	replaceModeFactories(t, map[string]func(Options) Runner{
		"arp": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, ErrModeUnavailable })
		},
		"icmp-echo": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, ErrModeUnavailable })
		},
		"tcp-syn": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { synCalls++; return Result{}, ErrModeUnavailable })
		},
		"tcp-connect": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				connectCalls++
				return Result{Matched: true, Method: "tcp-connect"}, nil
			})
		},
		"tcp-ack": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { ackCalls++; return Result{}, nil })
		},
	})

	result, err := runLinuxAutomatic(context.Background(), "127.0.0.1", Options{Ports: []int{80}})
	if err != nil || !result.Matched || result.Method != "tcp-connect" {
		t.Fatalf("unexpected automatic result: %+v, %v", result, err)
	}
	if synCalls != 1 || connectCalls != 1 || ackCalls != 0 {
		t.Fatalf("unexpected fallback calls: syn=%d connect=%d ack=%d", synCalls, connectCalls, ackCalls)
	}
}

func TestRunAutomaticRunsICMPAndSYNConcurrently(t *testing.T) {
	started := make(chan string, 2)
	release := make(chan struct{})
	replaceModeFactories(t, map[string]func(Options) Runner{
		"arp": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, ErrModeUnavailable })
		},
		"icmp-echo": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { started <- "icmp"; <-release; return Result{}, nil })
		},
		"tcp-syn": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { started <- "syn"; <-release; return Result{}, nil })
		},
		"tcp-connect": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, nil })
		},
		"tcp-ack": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, nil })
		},
	})

	done := make(chan error, 1)
	go func() {
		_, err := runLinuxAutomatic(context.Background(), "127.0.0.1", Options{Ports: []int{80}})
		done <- err
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("ICMP and SYN did not overlap")
		}
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected automatic error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("automatic round did not finish")
	}
}

func TestRunAutomaticMatchCancelsAndWaitsForOtherLaneCleanup(t *testing.T) {
	synStarted := make(chan struct{})
	cleanupStarted := make(chan struct{})
	allowCleanup := make(chan struct{})
	connectCalls := 0
	replaceModeFactories(t, map[string]func(Options) Runner{
		"arp": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, ErrModeUnavailable })
		},
		"icmp-echo": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				<-synStarted
				return Result{Matched: true, Method: "icmp-echo"}, nil
			})
		},
		"tcp-syn": func(Options) Runner {
			return RunnerFunc(func(ctx context.Context, _ string) (Result, error) {
				close(synStarted)
				<-ctx.Done()
				close(cleanupStarted)
				<-allowCleanup
				return Result{}, ctx.Err()
			})
		},
		"tcp-connect": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				connectCalls++
				return Result{}, nil
			})
		},
		"tcp-ack": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, nil })
		},
	})

	type runResult struct {
		result Result
		err    error
	}
	done := make(chan runResult, 1)
	go func() {
		result, err := runLinuxAutomatic(context.Background(), "127.0.0.1", Options{Ports: []int{80}})
		done <- runResult{result: result, err: err}
	}()

	<-cleanupStarted
	select {
	case got := <-done:
		t.Fatalf("automatic run returned before lane cleanup: %+v", got)
	default:
	}
	close(allowCleanup)
	got := <-done
	if got.err != nil || !got.result.Matched || got.result.Method != "icmp-echo" {
		t.Fatalf("unexpected automatic result after cleanup: %+v, %v", got.result, got.err)
	}
	if connectCalls != 0 {
		t.Fatalf("match-triggered cancellation started Connect %d times", connectCalls)
	}
}

func TestRunAutomaticCallerCancellationWaitsForLaneCleanup(t *testing.T) {
	started := make(chan struct{}, 2)
	cleanupStarted := make(chan struct{}, 2)
	allowCleanup := make(chan struct{})
	blockingRunner := func(Options) Runner {
		return RunnerFunc(func(ctx context.Context, _ string) (Result, error) {
			started <- struct{}{}
			<-ctx.Done()
			cleanupStarted <- struct{}{}
			<-allowCleanup
			return Result{}, ctx.Err()
		})
	}
	replaceModeFactories(t, map[string]func(Options) Runner{
		"arp": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, ErrModeUnavailable })
		},
		"icmp-echo":   blockingRunner,
		"tcp-syn":     blockingRunner,
		"tcp-connect": blockingRunner,
		"tcp-ack":     blockingRunner,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := runLinuxAutomatic(ctx, "127.0.0.1", Options{Ports: []int{80}})
		done <- err
	}()
	<-started
	<-started
	cancel()
	<-cleanupStarted
	<-cleanupStarted
	select {
	case err := <-done:
		t.Fatalf("automatic run returned before canceled lanes cleaned up: %v", err)
	default:
	}
	close(allowCleanup)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected parent context cancellation, got %v", err)
	}
}

func TestRunAutomaticMatchPreventsSYNFallbackConnect(t *testing.T) {
	synStarted := make(chan struct{})
	connectCalls := 0
	replaceModeFactories(t, map[string]func(Options) Runner{
		"arp": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, ErrModeUnavailable })
		},
		"icmp-echo": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				<-synStarted
				return Result{Matched: true, Method: "icmp-echo"}, nil
			})
		},
		"tcp-syn": func(Options) Runner {
			return RunnerFunc(func(ctx context.Context, _ string) (Result, error) {
				close(synStarted)
				<-ctx.Done()
				return Result{}, ErrModeUnavailable
			})
		},
		"tcp-connect": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				connectCalls++
				return Result{}, nil
			})
		},
		"tcp-ack": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, nil })
		},
	})

	result, err := runLinuxAutomatic(context.Background(), "127.0.0.1", Options{Ports: []int{80}})
	if err != nil || !result.Matched || result.Method != "icmp-echo" {
		t.Fatalf("unexpected automatic result: %+v, %v", result, err)
	}
	if connectCalls != 0 {
		t.Fatalf("match-triggered cancellation started Connect %d times", connectCalls)
	}
}

func TestRunAutomaticUsableNoSignalSuppressesOtherLaneFailure(t *testing.T) {
	tests := []struct {
		name       string
		synResult  Result
		wantMatch  bool
		wantMethod string
		wantErr    error
	}{
		{name: "usable no signal suppresses failure"},
		{name: "match wins", synResult: Result{Matched: true, Method: "tcp-syn"}, wantMatch: true, wantMethod: "tcp-syn"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			replaceModeFactories(t, map[string]func(Options) Runner{
				"arp": func(Options) Runner {
					return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, ErrModeUnavailable })
				},
				"icmp-echo": func(Options) Runner {
					return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, ErrProbeFailed })
				},
				"tcp-syn": func(Options) Runner {
					return RunnerFunc(func(context.Context, string) (Result, error) { return tt.synResult, nil })
				},
				"tcp-connect": func(Options) Runner {
					return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, nil })
				},
				"tcp-ack": func(Options) Runner {
					return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, nil })
				},
			})

			result, err := runLinuxAutomatic(context.Background(), "127.0.0.1", Options{Ports: []int{80}})
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected %v, got result=%+v err=%v", tt.wantErr, result, err)
				}
				return
			}
			if err != nil || result.Matched != tt.wantMatch || result.Method != tt.wantMethod {
				t.Fatalf("unexpected automatic result: %+v, %v", result, err)
			}
		})
	}
}

func TestRunAutomaticSYNNoSignalDoesNotFallBackToConnect(t *testing.T) {
	var connectCalls int
	replaceModeFactories(t, map[string]func(Options) Runner{
		"arp": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, ErrModeUnavailable })
		},
		"icmp-echo": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, nil })
		},
		"tcp-syn": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, nil })
		},
		"tcp-connect": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { connectCalls++; return Result{}, nil })
		},
		"tcp-ack": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, nil })
		},
	})

	result, err := runLinuxAutomatic(context.Background(), "127.0.0.1", Options{Ports: []int{80}})
	if err != nil || result.Matched {
		t.Fatalf("unexpected automatic result: %+v, %v", result, err)
	}
	if connectCalls != 0 {
		t.Fatalf("SYN normal no-signal must not start Connect, got %d calls", connectCalls)
	}
}

func TestRunAutomaticCachesICMPAndSYNUnavailableWithinCall(t *testing.T) {
	var icmpCalls, synCalls, connectCalls int
	replaceModeFactories(t, map[string]func(Options) Runner{
		"arp": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, ErrModeUnavailable })
		},
		"icmp-echo": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { icmpCalls++; return Result{}, ErrModeUnavailable })
		},
		"tcp-syn": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { synCalls++; return Result{}, ErrModeUnavailable })
		},
		"tcp-connect": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { connectCalls++; return Result{}, nil })
		},
		"tcp-ack": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, nil })
		},
	})

	_, err := runLinuxAutomatic(context.Background(), "127.0.0.1", Options{Ports: []int{80}, Retries: 2})
	if err != nil {
		t.Fatalf("unexpected automatic error: %v", err)
	}
	if icmpCalls != 1 || synCalls != 1 || connectCalls != 2 {
		t.Fatalf("unexpected capability caching: icmp=%d syn=%d connect=%d", icmpCalls, synCalls, connectCalls)
	}
}

func TestRunAutomaticRechecksUnavailableCapabilitiesOnNextRun(t *testing.T) {
	available := false
	var icmpCalls, synCalls int
	replaceModeFactories(t, map[string]func(Options) Runner{
		"arp": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, ErrModeUnavailable })
		},
		"icmp-echo": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				icmpCalls++
				if !available {
					return Result{}, ErrModeUnavailable
				}
				return Result{Matched: true, Method: "icmp-echo"}, nil
			})
		},
		"tcp-syn": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				synCalls++
				if !available {
					return Result{}, ErrModeUnavailable
				}
				return Result{}, nil
			})
		},
		"tcp-connect": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, nil })
		},
		"tcp-ack": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, nil })
		},
	})

	first, err := runLinuxAutomatic(context.Background(), "127.0.0.1", Options{Ports: []int{80}, Retries: 2})
	if err != nil || first.Matched {
		t.Fatalf("unexpected unavailable first run: result=%+v err=%v", first, err)
	}
	if icmpCalls != 1 || synCalls != 1 {
		t.Fatalf("unavailable capabilities were not cached within first run: icmp=%d syn=%d", icmpCalls, synCalls)
	}

	available = true
	second, err := runLinuxAutomatic(context.Background(), "127.0.0.1", Options{Ports: []int{80}})
	if err != nil || !second.Matched || second.Method != "icmp-echo" {
		t.Fatalf("new run did not recheck recovered capability: result=%+v err=%v", second, err)
	}
	if icmpCalls != 2 || synCalls != 2 {
		t.Fatalf("new run reused unavailable cache: icmp=%d syn=%d", icmpCalls, synCalls)
	}
}

func TestRunAutomaticCachesAllUnavailableCapabilitiesWithinCall(t *testing.T) {
	calls := map[string]int{}
	var callsMu sync.Mutex
	unavailable := func(mode string) func(Options) Runner {
		return func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				callsMu.Lock()
				calls[mode]++
				callsMu.Unlock()
				return Result{}, ErrModeUnavailable
			})
		}
	}
	replaceModeFactories(t, map[string]func(Options) Runner{
		"arp":         unavailable("arp"),
		"icmp-echo":   unavailable("icmp-echo"),
		"tcp-syn":     unavailable("tcp-syn"),
		"tcp-connect": unavailable("tcp-connect"),
		"tcp-ack":     unavailable("tcp-ack"),
	})

	_, err := runLinuxAutomatic(context.Background(), "127.0.0.1", Options{Ports: []int{80}, Retries: 3})
	if !errors.Is(err, ErrNoUsableModes) {
		t.Fatalf("expected ErrNoUsableModes, got %v", err)
	}
	callsMu.Lock()
	defer callsMu.Unlock()
	for _, mode := range []string{"arp", "icmp-echo", "tcp-syn", "tcp-connect"} {
		if calls[mode] != 1 {
			t.Fatalf("expected unavailable %s to run once, got %d", mode, calls[mode])
		}
	}
	if calls["tcp-ack"] != 0 {
		t.Fatalf("automatic policy must not run ACK, got %d calls", calls["tcp-ack"])
	}
}

func TestRunAutomaticUsableNoSignalSuppressesUncausedLaneCancellation(t *testing.T) {
	replaceModeFactories(t, map[string]func(Options) Runner{
		"arp": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, ErrModeUnavailable })
		},
		"icmp-echo": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, context.Canceled })
		},
		"tcp-syn": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, nil })
		},
		"tcp-connect": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, nil })
		},
		"tcp-ack": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, nil })
		},
	})

	result, err := runLinuxAutomatic(context.Background(), "127.0.0.1", Options{Ports: []int{80}})
	if err != nil || result.Matched {
		t.Fatalf("expected effective TCP no-signal to keep target unconfirmed: result=%+v err=%v", result, err)
	}
}

func TestRunAutomaticIPMatchWinsAfterARPFailure(t *testing.T) {
	replaceModeFactories(t, map[string]func(Options) Runner{
		"arp": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, ErrProbeFailed })
		},
		"icmp-echo": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				return Result{Matched: true, Method: "icmp-echo"}, nil
			})
		},
		"tcp-syn": func(Options) Runner {
			return RunnerFunc(func(ctx context.Context, _ string) (Result, error) {
				<-ctx.Done()
				return Result{}, ctx.Err()
			})
		},
		"tcp-connect": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, nil })
		},
		"tcp-ack": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, nil })
		},
	})

	result, err := runLinuxAutomatic(context.Background(), "127.0.0.1", Options{Ports: []int{80}})
	if err != nil || !result.Matched || result.Method != "icmp-echo" {
		t.Fatalf("IP match should win after retained ARP failure: %+v, %v", result, err)
	}
}

func TestRunAutomaticAllIPProbesUnroutableReturnsError(t *testing.T) {
	unroutable := errors.Join(ErrProbeFailed, errors.New("network is unreachable"))
	replaceModeFactories(t, map[string]func(Options) Runner{
		"arp": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, ErrModeUnavailable })
		},
		"icmp-echo": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, unroutable })
		},
		"tcp-syn": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, unroutable })
		},
	})
	result, err := runLinuxAutomatic(context.Background(), "192.0.2.10", Options{Ports: []int{80}})
	if result.Matched || !errors.Is(err, ErrProbeFailed) || !strings.Contains(err.Error(), "network is unreachable") {
		t.Fatalf("expected route failure, not a normal no-signal result: result=%+v err=%v", result, err)
	}
}

func TestRunAutomaticARPFailureWithIPNoSignalReturnsUnconfirmed(t *testing.T) {
	replaceModeFactories(t, map[string]func(Options) Runner{
		"arp": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, ErrProbeFailed })
		},
		"icmp-echo": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, nil })
		},
		"tcp-syn": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, nil })
		},
		"tcp-connect": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, nil })
		},
		"tcp-ack": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) { return Result{}, nil })
		},
	})

	result, err := runLinuxAutomatic(context.Background(), "127.0.0.1", Options{Ports: []int{80}})
	if err != nil || result.Matched {
		t.Fatalf("expected usable IP no-signal to keep target unconfirmed: result=%+v err=%v", result, err)
	}
}

func TestRunStopsOnFirstMatchedMode(t *testing.T) {
	var thirdCalls int
	replaceModeFactories(t, map[string]func(Options) Runner{
		"first": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				return Result{}, nil
			})
		},
		"second": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				return Result{Matched: true, Method: "second"}, nil
			})
		},
		"third": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				thirdCalls++
				return Result{Matched: true, Method: "third"}, nil
			})
		},
	})

	result, err := Run(context.Background(), "127.0.0.1", Options{
		Modes:   []string{"first", "second", "third"},
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Matched || result.Method != "second" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if thirdCalls != 0 {
		t.Fatalf("expected matched mode to short-circuit, third mode ran %d times", thirdCalls)
	}
}

func TestRunExplicitTCPACKHonorsCallerOrder(t *testing.T) {
	var order []string
	replaceModeFactories(t, map[string]func(Options) Runner{
		"tcp-ack": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				order = append(order, "tcp-ack")
				return Result{}, nil
			})
		},
		"tcp-connect": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				order = append(order, "tcp-connect")
				return Result{Matched: true, Method: "tcp-connect"}, nil
			})
		},
	})

	result, err := Run(context.Background(), "127.0.0.1", Options{
		Modes: []string{"tcp-ack", "tcp-connect"},
		Ports: []int{80},
	})
	if err != nil || !result.Matched || result.Method != "tcp-connect" {
		t.Fatalf("unexpected explicit result: result=%+v err=%v", result, err)
	}
	if got, want := strings.Join(order, ","), "tcp-ack,tcp-connect"; got != want {
		t.Fatalf("explicit mode order changed: want %s, got %s", want, got)
	}
}

func TestRunContinuesAfterUnavailableOrFailedModeWhenLaterModeMatches(t *testing.T) {
	tests := []struct {
		name     string
		firstErr error
	}{
		{name: "unavailable", firstErr: errors.Join(ErrModeUnavailable, errors.New("missing capability"))},
		{name: "failed", firstErr: errors.Join(ErrProbeFailed, errors.New("resource exhausted"))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			replaceModeFactories(t, map[string]func(Options) Runner{
				"first": func(Options) Runner {
					return RunnerFunc(func(context.Context, string) (Result, error) {
						return Result{}, tt.firstErr
					})
				},
				"second": func(Options) Runner {
					return RunnerFunc(func(context.Context, string) (Result, error) {
						return Result{Matched: true, Method: "second"}, nil
					})
				},
			})

			result, err := Run(context.Background(), "127.0.0.1", Options{Modes: []string{"first", "second"}})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !result.Matched || result.Method != "second" {
				t.Fatalf("unexpected result: %+v", result)
			}
		})
	}
}

func TestRunUnavailablePlusNoSignalReturnsNoMatch(t *testing.T) {
	replaceModeFactories(t, map[string]func(Options) Runner{
		"unavailable": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				return Result{}, errors.Join(ErrModeUnavailable, errors.New("missing command"))
			})
		},
		"silent": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				return Result{}, nil
			})
		},
	})

	result, err := Run(context.Background(), "127.0.0.1", Options{Modes: []string{"unavailable", "silent"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Matched {
		t.Fatalf("expected no match, got %+v", result)
	}
}

func TestRunProbeFailurePlusNoSignalReturnsUnconfirmed(t *testing.T) {
	replaceModeFactories(t, map[string]func(Options) Runner{
		"failed": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				return Result{}, errors.Join(ErrProbeFailed, errors.New("first failure"))
			})
		},
		"silent": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				return Result{}, nil
			})
		},
	})

	result, err := Run(context.Background(), "127.0.0.1", Options{Modes: []string{"failed", "silent"}})
	if err != nil || result.Matched {
		t.Fatalf("expected usable no-signal to keep target unconfirmed: result=%+v err=%v", result, err)
	}
}

func TestRunReturnsAllUnavailableReasons(t *testing.T) {
	replaceModeFactories(t, map[string]func(Options) Runner{
		"first": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				return Result{}, errors.Join(ErrModeUnavailable, errors.New("first reason"))
			})
		},
		"second": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				return Result{}, errors.Join(ErrModeUnavailable, errors.New("second reason"))
			})
		},
	})

	_, err := Run(context.Background(), "127.0.0.1", Options{Modes: []string{"first", "second"}})
	if !errors.Is(err, ErrNoUsableModes) {
		t.Fatalf("expected ErrNoUsableModes, got %v", err)
	}
	if !errors.Is(err, ErrModeUnavailable) {
		t.Fatalf("expected unavailable causes to be retained, got %v", err)
	}
	if !strings.Contains(err.Error(), "first reason") || !strings.Contains(err.Error(), "second reason") {
		t.Fatalf("expected both unavailable reasons, got %v", err)
	}
	if strings.Index(err.Error(), "first reason") > strings.Index(err.Error(), "second reason") {
		t.Fatalf("expected configured mode order in error, got %v", err)
	}
}

func TestRunRejectsInvalidOptionsBeforeStartingProbes(t *testing.T) {
	var calls int
	probeFactory := func(Options) Runner {
		return RunnerFunc(func(context.Context, string) (Result, error) {
			calls++
			return Result{}, nil
		})
	}
	replaceModeFactories(t, map[string]func(Options) Runner{
		"tcp-connect": probeFactory,
		"tcp-syn":     probeFactory,
		"tcp-ack":     probeFactory,
	})

	tests := []struct {
		name string
		ip   string
		opts Options
	}{
		{name: "invalid target", ip: "not-an-ip", opts: Options{Modes: []string{"tcp-connect"}, Ports: []int{80}}},
		{name: "unknown mode", ip: "127.0.0.1", opts: Options{Modes: []string{"typo"}}},
		{name: "missing connect ports", ip: "127.0.0.1", opts: Options{Modes: []string{"tcp-connect"}}},
		{name: "missing syn ports", ip: "127.0.0.1", opts: Options{Modes: []string{"tcp-syn"}}},
		{name: "missing ack ports", ip: "127.0.0.1", opts: Options{Modes: []string{"tcp-ack"}}},
		{name: "missing automatic ports", ip: "127.0.0.1", opts: Options{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Run(context.Background(), tt.ip, tt.opts)
			if !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("expected ErrInvalidOptions, got %v", err)
			}
		})
	}
	if calls != 0 {
		t.Fatalf("expected invalid options to stop before probes, got %d calls", calls)
	}
}

func TestRunRetriesOnlyNormalNoSignal(t *testing.T) {
	var calls int
	replaceModeFactories(t, map[string]func(Options) Runner{
		"silent": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				calls++
				return Result{}, nil
			})
		},
	})

	result, err := Run(context.Background(), "127.0.0.1", Options{Modes: []string{"silent"}, Retries: 2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Matched {
		t.Fatalf("expected no match, got %+v", result)
	}
	if calls != 2 {
		t.Fatalf("expected two total attempt rounds, got %d", calls)
	}
}

func TestRunDoesNotRetryUnavailableOrFailedMode(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "unavailable", err: ErrModeUnavailable},
		{name: "failed", err: ErrProbeFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls int
			replaceModeFactories(t, map[string]func(Options) Runner{
				"mode": func(Options) Runner {
					return RunnerFunc(func(context.Context, string) (Result, error) {
						calls++
						return Result{}, tt.err
					})
				},
			})

			_, _ = Run(context.Background(), "127.0.0.1", Options{Modes: []string{"mode"}, Retries: 3})
			if calls != 1 {
				t.Fatalf("expected one attempt, got %d", calls)
			}
		})
	}
}

func TestRunDefaultsToOneAttemptRound(t *testing.T) {
	var calls int
	replaceModeFactories(t, map[string]func(Options) Runner{
		"silent": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				calls++
				return Result{}, nil
			})
		},
	})

	_, err := Run(context.Background(), "127.0.0.1", Options{Modes: []string{"silent"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected one default attempt round, got %d", calls)
	}
}

func TestRunCancellationAfterNoSignalDoesNotStartNextRound(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls int
	replaceModeFactories(t, map[string]func(Options) Runner{
		"silent": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				calls++
				cancel()
				return Result{}, nil
			})
		},
	})

	_, err := Run(ctx, "127.0.0.1", Options{Modes: []string{"silent"}, Retries: 3})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected cancellation to stop retries, got %d calls", calls)
	}
}

func TestRunParentCancellationWinsOverUnreturnedMatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	replaceModeFactories(t, map[string]func(Options) Runner{
		"matched": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				cancel()
				return Result{Matched: true, Method: "matched"}, nil
			})
		},
	})

	result, err := Run(ctx, "127.0.0.1", Options{Modes: []string{"matched"}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got result=%+v err=%v", result, err)
	}
}
