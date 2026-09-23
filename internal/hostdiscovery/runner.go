package hostdiscovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
)

var modeFactories = map[string]func(Options) Runner{
	"tcp-connect": newTCPConnectRunner,
	"icmp-echo":   newICMPEchoRunner,
	"tcp-syn":     newTCPSYNRunner,
	"tcp-ack":     newTCPACKRunner,
	"arp":         newARPRunner,
}

// modeOutcome is the normalized result of one concrete probe attempt.
// It deliberately keeps execution classification private: the public result
// remains the stable Matched/Method pair.
type modeOutcome struct {
	result      Result
	usable      bool
	unavailable bool
	failed      bool
	err         error
}

func Run(ctx context.Context, ip string, opts Options) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	normalized, err := validateOptions(ip, opts)
	if err != nil {
		return Result{}, err
	}
	if len(normalized.Modes) == 0 {
		return runAutomatic(ctx, ip, normalized)
	}
	return runExplicit(ctx, ip, normalized)
}

// runExplicit retains the historical caller-ordered execution semantics.
func runExplicit(ctx context.Context, ip string, opts Options) (Result, error) {
	attempts := optionAttempts(opts)
	var issues []error
	usableModes := 0
	probeFailed := false

	for _, mode := range opts.Modes {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}

		modeUsable := false
		for attempt := 0; attempt < attempts; attempt++ {
			if err := ctx.Err(); err != nil {
				return Result{}, err
			}
			outcome := runModeAttempt(ctx, ip, mode, opts)
			if err := ctx.Err(); err != nil {
				return Result{}, err
			}
			if outcome.usable {
				modeUsable = true
				if outcome.result.Matched {
					return outcome.result, nil
				}
				continue
			}
			issues = append(issues, outcome.err)
			probeFailed = probeFailed || outcome.failed
			break
		}
		if modeUsable {
			usableModes++
		}
	}

	if usableModes > 0 {
		return Result{}, nil
	}
	if probeFailed {
		return Result{}, errors.Join(issues...)
	}
	return Result{}, errors.Join(append([]error{ErrNoUsableModes}, issues...)...)
}

func optionAttempts(opts Options) int {
	if opts.Retries > 0 {
		return opts.Retries
	}
	return 1
}

func runModeAttempt(ctx context.Context, ip, mode string, opts Options) modeOutcome {
	runner := modeFactories[mode](opts)
	result, runErr := runner.Run(ctx, ip)
	if runErr == nil {
		return modeOutcome{result: result, usable: true}
	}

	wrapped := wrapModeError(mode, runErr)
	outcome := modeOutcome{err: wrapped}
	switch {
	case errors.Is(runErr, ErrProbeFailed):
		outcome.failed = true
	case errors.Is(runErr, ErrModeUnavailable):
		outcome.unavailable = true
	default:
		outcome.failed = true
		outcome.err = fmt.Errorf("%w: %w", ErrProbeFailed, wrapped)
	}
	return outcome
}

type automaticState struct {
	arpUnavailable     bool
	icmpUnavailable    bool
	synUnavailable     bool
	connectUnavailable bool
}

type automaticPlan struct {
	arp     bool
	icmp    bool
	syn     bool
	connect bool
}

// automaticPlanFor maps the runtime platform and target address family to
// candidate lanes. Actual route and socket capability checks stay in runners.
func automaticPlanFor(platform, ip string) automaticPlan {
	parsed := net.ParseIP(ip)
	ipv4 := parsed != nil && parsed.To4() != nil
	switch platform {
	case "linux":
		return automaticPlan{arp: ipv4, icmp: true, syn: ipv4, connect: true}
	case "darwin":
		return automaticPlan{icmp: true, connect: true}
	default:
		return automaticPlan{connect: true}
	}
}

type automaticRound struct {
	outcomes map[string]modeOutcome
	matched  Result
}

// runAutomatic chooses probes for one target. Linux IPv4 attempts ARP first;
// its own route/interface/socket checks decide whether ARP is a usable,
// on-link probe. A usable ARP probe replaces IP probing for that round.
func runAutomatic(ctx context.Context, ip string, opts Options) (Result, error) {
	return runAutomaticForPlatform(ctx, ip, opts, runtime.GOOS)
}

// runAutomaticForPlatform executes the target-level automatic state machine
// using the supplied platform plan; production calls always pass runtime.GOOS.
func runAutomaticForPlatform(ctx context.Context, ip string, opts Options, platform string) (Result, error) {
	attempts := optionAttempts(opts)
	state := automaticState{}
	plan := automaticPlanFor(platform, ip)
	outcomes := make(map[string][]modeOutcome, 4)

	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}

		arp := modeOutcome{}
		if plan.arp && !state.arpUnavailable {
			arp = runModeAttempt(ctx, ip, "arp", opts)
			outcomes["arp"] = append(outcomes["arp"], arp)
			if err := ctx.Err(); err != nil {
				return Result{}, err
			}
			if arp.usable {
				if arp.result.Matched {
					return arp.result, nil
				}
				// A route-confirmed ARP round is intentionally ARP-only.
				continue
			}
			if arp.unavailable {
				state.arpUnavailable = true
			}
		}

		ipRound, err := runAutomaticIPRound(ctx, ip, opts, plan, &state)
		for mode, outcome := range ipRound.outcomes {
			outcomes[mode] = append(outcomes[mode], outcome)
		}
		if err != nil {
			return Result{}, err
		}
		if ipRound.matched.Matched {
			return ipRound.matched, nil
		}
		// Execution failures are useful diagnostics but are not retried as
		// ordinary no-signal rounds. ARP failures still get this IP chance.
		if arp.failed || roundFailed(ipRound) || automaticIPExhausted(plan, state) {
			break
		}
	}

	return summarizeAutomatic(outcomes)
}

// runAutomaticIPRound overlaps the ICMP and TCP lanes, performs only the
// SYN-unavailable Connect fallback, and drains every started lane before return.
func runAutomaticIPRound(ctx context.Context, ip string, opts Options, plan automaticPlan, state *automaticState) (automaticRound, error) {
	roundCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type laneResult struct {
		mode    string
		outcome modeOutcome
	}
	tcpMode := ""
	if plan.syn && !state.synUnavailable {
		tcpMode = "tcp-syn"
	} else if plan.connect && !state.connectUnavailable {
		tcpMode = "tcp-connect"
	}
	lanes := 0
	if plan.icmp && !state.icmpUnavailable {
		lanes++
	}
	if tcpMode != "" {
		lanes++
	}
	results := make(chan laneResult, lanes+1)

	if plan.icmp && !state.icmpUnavailable {
		go func() {
			results <- laneResult{mode: "icmp-echo", outcome: runModeAttempt(roundCtx, ip, "icmp-echo", opts)}
		}()
	}
	if tcpMode != "" {
		go func(mode string) {
			outcome := runModeAttempt(roundCtx, ip, mode, opts)
			if mode == "tcp-syn" && outcome.unavailable && plan.connect && !state.connectUnavailable {
				results <- laneResult{mode: mode, outcome: outcome}
				if err := roundCtx.Err(); err != nil {
					// Preserve the two-result lane accounting without opening a
					// fallback socket after another lane has already matched.
					results <- laneResult{mode: "tcp-connect", outcome: modeOutcome{err: err}}
					return
				}
				results <- laneResult{mode: "tcp-connect", outcome: runModeAttempt(roundCtx, ip, "tcp-connect", opts)}
				return
			}
			results <- laneResult{mode: mode, outcome: outcome}
		}(tcpMode)
	}

	round := automaticRound{outcomes: make(map[string]modeOutcome, 3)}
	remaining := lanes
	for remaining > 0 {
		entry := <-results
		remaining--
		// A SYN-unavailable lane adds an immediate Connect attempt.
		if entry.mode == "tcp-syn" && entry.outcome.unavailable {
			remaining++
		}
		if err := ctx.Err(); err != nil {
			// Continue draining below so runner cleanup completes before the
			// caller cancellation is returned.
			cancel()
		}
		if entry.outcome.usable && entry.outcome.result.Matched && !round.matched.Matched {
			round.matched = entry.outcome.result
			cancel()
		}
		// Only cancellation triggered by a confirmed match is suppressed.
		// An independent lane cancellation remains an execution failure.
		if errors.Is(entry.outcome.err, context.Canceled) && ctx.Err() == nil && round.matched.Matched {
			continue
		}
		round.outcomes[entry.mode] = entry.outcome
	}
	if err := ctx.Err(); err != nil {
		return automaticRound{}, err
	}
	if outcome, ok := round.outcomes["icmp-echo"]; ok && outcome.unavailable {
		state.icmpUnavailable = true
	}
	if outcome, ok := round.outcomes["tcp-syn"]; ok && outcome.unavailable {
		state.synUnavailable = true
	}
	if outcome, ok := round.outcomes["tcp-connect"]; ok && outcome.unavailable {
		state.connectUnavailable = true
	}
	return round, nil
}

// automaticIPExhausted reports whether all platform-eligible IP lanes have
// already returned capability-unavailable during this Run call.
func automaticIPExhausted(plan automaticPlan, state automaticState) bool {
	icmpExhausted := !plan.icmp || state.icmpUnavailable
	tcpExhausted := !plan.connect || state.connectUnavailable
	if plan.syn && !state.synUnavailable {
		tcpExhausted = false
	}
	return icmpExhausted && tcpExhausted
}

func roundFailed(round automaticRound) bool {
	for _, outcome := range round.outcomes {
		if outcome.failed {
			return true
		}
	}
	return false
}

// summarizeAutomatic prioritizes an effective no-signal probe over errors
// from other modes; when none could run, it retains their diagnostic causes.
func summarizeAutomatic(outcomes map[string][]modeOutcome) (Result, error) {
	orderedModes := []string{"arp", "icmp-echo", "tcp-syn", "tcp-connect"}
	var issues []error
	usable := false
	failed := false
	for _, mode := range orderedModes {
		for _, outcome := range outcomes[mode] {
			usable = usable || outcome.usable
			failed = failed || outcome.failed
			if outcome.err != nil {
				issues = append(issues, outcome.err)
			}
		}
	}
	if usable {
		return Result{}, nil
	}
	if failed {
		return Result{}, errors.Join(issues...)
	}
	return Result{}, errors.Join(append([]error{ErrNoUsableModes}, issues...)...)
}

// ValidateOptions verifies host-discovery probe configuration without
// inspecting or probing a target. Empty Modes requests the internal automatic
// policy, which may use TCP and therefore still requires a valid TCP port.
func ValidateOptions(opts Options) error {
	if len(opts.Modes) == 0 {
		if len(validPorts(opts.Ports)) == 0 {
			return fmt.Errorf("%w: automatic discovery requires at least one valid TCP port", ErrInvalidOptions)
		}
		return nil
	}

	needsPorts := false
	for _, mode := range opts.Modes {
		if _, ok := modeFactories[mode]; !ok {
			return fmt.Errorf("%w: unknown mode %q", ErrInvalidOptions, mode)
		}
		if mode == "tcp-connect" || mode == "tcp-syn" || mode == "tcp-ack" {
			needsPorts = true
		}
	}
	if needsPorts && len(validPorts(opts.Ports)) == 0 {
		return fmt.Errorf("%w: TCP discovery mode requires at least one valid port", ErrInvalidOptions)
	}
	return nil
}

func validateOptions(ip string, opts Options) (Options, error) {
	if net.ParseIP(ip) == nil {
		return Options{}, fmt.Errorf("%w: target %q is not an IP address", ErrInvalidOptions, ip)
	}
	if err := ValidateOptions(opts); err != nil {
		return Options{}, err
	}

	normalized := opts
	normalized.Modes = append([]string(nil), opts.Modes...)
	if len(normalized.Modes) == 0 {
		normalized.Ports = uniqueValidPorts(opts.Ports)
	} else {
		normalized.Ports = validPorts(opts.Ports)
	}
	return normalized, nil
}

func validPorts(ports []int) []int {
	valid := make([]int, 0, len(ports))
	for _, port := range ports {
		if port >= 1 && port <= 65535 {
			valid = append(valid, port)
		}
	}
	return valid
}

func wrapModeError(mode string, err error) error {
	return fmt.Errorf("mode %s: %w", mode, err)
}

func unavailableRunner(method, reason string) Runner {
	return RunnerFunc(func(context.Context, string) (Result, error) {
		return Result{}, fmt.Errorf("%w: mode %s: %s", ErrModeUnavailable, method, reason)
	})
}
