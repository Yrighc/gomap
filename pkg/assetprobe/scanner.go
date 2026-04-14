package assetprobe

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	appassets "github.com/yrighc/gomap/app"
	"github.com/yrighc/gomap/config/logger"
	"github.com/yrighc/gomap/config/probes"
	"github.com/yrighc/gomap/config/service"
	"github.com/yrighc/gomap/internal/achieve"
	"github.com/yrighc/gomap/internal/crawlweb"
	"github.com/yrighc/gomap/internal/tcpservices"
	"github.com/yrighc/gomap/internal/updservices"
)

var (
	initOnce          sync.Once
	initErr           error
	portLimiterMu     sync.Mutex
	portLimiterByRate = make(map[int]*portRateLimiter)
)

type Scanner struct {
	opts Options
}

type portRateLimiter struct {
	ticker *time.Ticker
}

type batchTargetContext struct {
	index              int
	target             string
	resolvedIP         string
	protocol           Protocol
	timeout            time.Duration
	fingerprintSlots   chan struct{}
	fingerprintedCount int32
	collected          []PortResult
	mu                 sync.Mutex
}

type batchJob struct {
	targetIndex int
	port        int
}

// NewScanner 初始化探测所需资源（nmap 探针与服务字典），
// 每个进程只加载一次，并返回可复用的扫描器实例。
func NewScanner(opts Options) (*Scanner, error) {
	// 判断默认值，如果未传参数赋默认值
	applyDefaults(&opts)
	// 单例初始化，读配置文件
	initOnce.Do(func() {
		initErr = initAssets(opts)
	})
	if initErr != nil {
		return nil, initErr
	}
	return &Scanner{opts: opts}, nil
}

// Scan 是资产探测的主流程入口：
// 1) 读取请求参数，并与 Scanner 的默认配置合并
// 2) 解析目标地址，将域名统一解析成可连接的 IP
// 3) 解析端口表达式，得到去重且有序的端口列表
// 4) 基于 worker pool 并发执行 TCP/UDP 探测
// 5) 汇总结果，只保留开放端口，并计算统计信息
//
// 这里返回的 Ports 已经过滤，只包含 Open=true 的端口。
// 关闭端口不会出现在结果中，但仍会参与总扫描量与蜜罐判定计算。
func (s *Scanner) Scan(ctx context.Context, req ScanRequest) (*ScanResult, error) {
	if strings.TrimSpace(req.Target) == "" {
		return nil, errors.New("target is required")
	}
	if req.Protocol == "" {
		req.Protocol = ProtocolTCP
	}

	ports, err := normalizePorts(req.Ports, req.PortSpec)
	if err != nil {
		return nil, err
	}
	if len(ports) == 0 {
		return nil, errors.New("no valid ports")
	}

	targetHost := strings.TrimSpace(req.Target)
	resolvedIP, err := resolveTarget(targetHost)
	if err != nil {
		return nil, err
	}

	// 请求级参数优先级高于 Scanner 默认配置。
	// 这样既可以全局复用默认值，也可以在单次扫描时做覆盖。
	timeout := s.opts.Timeout
	if req.Timeout > 0 {
		timeout = req.Timeout
	}
	portConcurrency := s.opts.PortConcurrency
	if req.PortConcurrency > 0 {
		portConcurrency = req.PortConcurrency
	}
	portRateLimit := s.opts.PortRateLimit
	if req.PortRateLimit > 0 {
		portRateLimit = req.PortRateLimit
	}
	maxFingerprintPorts := s.opts.MaxFingerprintPorts
	if req.MaxFingerprintPorts > 0 {
		maxFingerprintPorts = req.MaxFingerprintPorts
	}
	honeypotOpenThreshold := s.opts.HoneypotOpenThreshold
	if req.HoneypotOpenThreshold > 0 {
		honeypotOpenThreshold = req.HoneypotOpenThreshold
	}
	honeypotOpenRatio := s.opts.HoneypotOpenRatio
	if req.HoneypotOpenRatio > 0 {
		honeypotOpenRatio = req.HoneypotOpenRatio
	}
	// 为 TCP 指纹识别准备“令牌桶”。
	// 端口连通后，只有拿到令牌的开放端口才会继续做深度服务识别。
	// 这样可以避免全开端口、portspoof、蜜罐类目标导致大量指纹探测拖慢整体扫描。
	var fingerprintSlots chan struct{}
	if req.Protocol == ProtocolTCP && maxFingerprintPorts > 0 {
		fingerprintSlots = make(chan struct{}, maxFingerprintPorts)
		for i := 0; i < maxFingerprintPorts; i++ {
			fingerprintSlots <- struct{}{}
		}
	}
	var fingerprintedCount int32
	portLimiter := getPortRateLimiter(portRateLimit)

	// jobs 负责分发待扫描端口，results 收集每个端口的探测结果。
	// 两者长度都按端口总数预分配，尽量降低 goroutine 间阻塞。
	jobs := make(chan int, len(ports))
	results := make(chan PortResult, len(ports))
	var wg sync.WaitGroup

	// 端口级并发 Worker 池：
	// 每个 worker 从 jobs 中读取一个端口并执行一次探测，直到队列耗尽或 ctx 被取消。
	for i := 0; i < portConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if err := waitPortRateLimit(ctx, portLimiter); err != nil {
					return
				}
				var r PortResult
				switch req.Protocol {
				case ProtocolUDP:
					r = s.scanUDPPort(targetHost, resolvedIP, p, timeout)
				default:
					r = s.scanTCPPort(targetHost, resolvedIP, p, timeout, fingerprintSlots, &fingerprintedCount)
				}
				results <- r
			}
		}()
	}

	for _, p := range ports {
		jobs <- p
	}
	close(jobs)
	wg.Wait()
	close(results)

	// 先收集原始结果，再统一排序和过滤。
	// 这样统计逻辑只需要遍历一次，后续 CLI / JSON 也能直接使用过滤后的结果。
	collected := make([]PortResult, 0, len(ports))
	for r := range results {
		collected = append(collected, r)
	}
	sort.Slice(collected, func(i, j int) bool { return collected[i].Port < collected[j].Port })

	openPorts := 0
	final := make([]PortResult, 0, len(collected))
	for _, r := range collected {
		// 当前产品策略：最终结果只返回开放端口。
		// 关闭端口在资产探测场景下价值较低，保留会显著放大 JSON / CSV 体积。
		if !r.Open {
			continue
		}
		openPorts++
		final = append(final, r)
	}
	fingerprintedOpenPorts := int(atomic.LoadInt32(&fingerprintedCount))
	skippedFingerprintPorts := openPorts - fingerprintedOpenPorts
	if skippedFingerprintPorts < 0 {
		skippedFingerprintPorts = 0
	}
	suspectedHoneypot := false
	honeypotReason := ""
	if req.Protocol == ProtocolTCP && len(collected) > 0 {
		// 蜜罐判定基于“全部已扫描端口”的开放比例，而不是过滤后的 final。
		// 否则一旦只保留开放端口，占比会永远是 100%，判定将失真。
		openRatio := float64(openPorts) / float64(len(collected))
		if openPorts >= honeypotOpenThreshold && openRatio >= honeypotOpenRatio {
			suspectedHoneypot = true
			honeypotReason = fmt.Sprintf("open ports=%d/%d(%.2f%%) >= threshold=%d and ratio=%.2f%%", openPorts, len(collected), openRatio*100, honeypotOpenThreshold, honeypotOpenRatio*100)
		}
	}

	return &ScanResult{
		Target:     targetHost,
		ResolvedIP: resolvedIP,
		Protocol:   req.Protocol,
		Meta: ScanMeta{
			OpenPorts:               openPorts,
			FingerprintedOpenPorts:  fingerprintedOpenPorts,
			SkippedFingerprintPorts: skippedFingerprintPorts,
			SuspectedHoneypot:       suspectedHoneypot,
			HoneypotReason:          honeypotReason,
		},
		Ports: final,
	}, nil
}

// ScanTargets 批量扫描多个目标，并复用同一组公共扫描参数。
// 它会把所有 (target, port) 任务展开到同一个全局任务池中，由 PortConcurrency 控制总并发，
// 并默认打乱执行顺序，以降低多目标顺序探测带来的规则化特征。
//
// 行为说明：
// 1) 目标会先做去空、去重，并保持输入顺序用于最终结果输出
// 2) 任务执行顺序会随机化，但返回结果仍按输入顺序组织
// 3) 单目标失败不会影响其他目标，失败信息会写入对应 TargetScanResult.Error
func (s *Scanner) ScanTargets(ctx context.Context, targets []string, opts ScanCommonOptions) (*BatchScanResult, error) {
	normalized := normalizeTargets(targets)
	if len(normalized) == 0 {
		return nil, errors.New("targets is required")
	}

	if opts.Protocol == "" {
		opts.Protocol = ProtocolTCP
	}
	ports, err := normalizePorts(opts.Ports, opts.PortSpec)
	if err != nil {
		return nil, err
	}
	if len(ports) == 0 {
		return nil, errors.New("no valid ports")
	}

	timeout := s.opts.Timeout
	if opts.Timeout > 0 {
		timeout = opts.Timeout
	}
	portConcurrency := s.opts.PortConcurrency
	if opts.PortConcurrency > 0 {
		portConcurrency = opts.PortConcurrency
	}
	portRateLimit := s.opts.PortRateLimit
	if opts.PortRateLimit > 0 {
		portRateLimit = opts.PortRateLimit
	}
	maxFingerprintPorts := s.opts.MaxFingerprintPorts
	if opts.MaxFingerprintPorts > 0 {
		maxFingerprintPorts = opts.MaxFingerprintPorts
	}
	honeypotOpenThreshold := s.opts.HoneypotOpenThreshold
	if opts.HoneypotOpenThreshold > 0 {
		honeypotOpenThreshold = opts.HoneypotOpenThreshold
	}
	honeypotOpenRatio := s.opts.HoneypotOpenRatio
	if opts.HoneypotOpenRatio > 0 {
		honeypotOpenRatio = opts.HoneypotOpenRatio
	}

	results := make([]TargetScanResult, len(normalized))
	contexts := make([]*batchTargetContext, len(normalized))
	for i, target := range normalized {
		results[i].Target = target
		resolvedIP, resolveErr := resolveTarget(target)
		if resolveErr != nil {
			results[i].Error = resolveErr.Error()
			continue
		}

		var fingerprintSlots chan struct{}
		if opts.Protocol == ProtocolTCP && maxFingerprintPorts > 0 {
			fingerprintSlots = make(chan struct{}, maxFingerprintPorts)
			for j := 0; j < maxFingerprintPorts; j++ {
				fingerprintSlots <- struct{}{}
			}
		}

		contexts[i] = &batchTargetContext{
			index:            i,
			target:           target,
			resolvedIP:       resolvedIP,
			protocol:         opts.Protocol,
			timeout:          timeout,
			fingerprintSlots: fingerprintSlots,
		}
	}

	jobs := make([]batchJob, 0, len(normalized)*len(ports))
	for idx, targetCtx := range contexts {
		if targetCtx == nil {
			continue
		}
		for _, port := range ports {
			jobs = append(jobs, batchJob{targetIndex: idx, port: port})
		}
	}
	shuffleBatchJobs(jobs)

	if portConcurrency <= 0 {
		portConcurrency = 1
	}
	if portConcurrency > len(jobs) && len(jobs) > 0 {
		portConcurrency = len(jobs)
	}

	jobCh := make(chan batchJob, len(jobs))
	for _, job := range jobs {
		jobCh <- job
	}
	close(jobCh)

	portLimiter := getPortRateLimiter(portRateLimit)
	var wg sync.WaitGroup
	for i := 0; i < portConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobCh {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if err := waitPortRateLimit(ctx, portLimiter); err != nil {
					return
				}

				targetCtx := contexts[job.targetIndex]
				if targetCtx == nil {
					continue
				}

				var portResult PortResult
				switch opts.Protocol {
				case ProtocolUDP:
					portResult = s.scanUDPPort(targetCtx.target, targetCtx.resolvedIP, job.port, timeout)
				default:
					portResult = s.scanTCPPort(
						targetCtx.target,
						targetCtx.resolvedIP,
						job.port,
						timeout,
						targetCtx.fingerprintSlots,
						&targetCtx.fingerprintedCount,
					)
				}

				targetCtx.mu.Lock()
				targetCtx.collected = append(targetCtx.collected, portResult)
				targetCtx.mu.Unlock()
			}
		}()
	}
	wg.Wait()

	for i, targetCtx := range contexts {
		if results[i].Error != "" || targetCtx == nil {
			if results[i].Error == "" {
				results[i].Error = "target context not initialized"
			}
			continue
		}
		results[i].Result = finalizeBatchTargetResult(targetCtx, honeypotOpenThreshold, honeypotOpenRatio)
	}

	if err := ctx.Err(); err != nil {
		for i := range results {
			if results[i].Result == nil && results[i].Error == "" {
				results[i].Error = err.Error()
			}
		}
		return &BatchScanResult{Results: results}, err
	}

	return &BatchScanResult{Results: results}, nil
}

// Probe 是单端口便捷封装，内部复用 Scan。
// 由于 Scan 现在只返回开放端口，所以当目标端口关闭时，这里返回一个 Open=false 的占位结果，
// 避免调用方因为空结果切片而额外处理错误分支。
func (s *Scanner) Probe(ctx context.Context, target string, port int, protocol Protocol) (*PortResult, error) {
	result, err := s.Scan(ctx, ScanRequest{
		Target:   target,
		Ports:    []int{port},
		Protocol: protocol,
	})
	if err != nil {
		return nil, err
	}
	if len(result.Ports) == 0 {
		return &PortResult{Port: port, Open: false}, nil
	}
	return &result.Ports[0], nil
}

// DetectHomepage 探测单个 URL，并返回标准化首页元信息。
// 默认返回完整 body，不返回 headers。
func (s *Scanner) DetectHomepage(ctx context.Context, rawURL string) (*HomepageResult, error) {
	return s.DetectHomepageWithOptions(ctx, rawURL, HomepageOptions{})
}

// DetectHomepageWithOptions 探测单个 URL，并允许控制 headers/body 的返回粒度。
func (s *Scanner) DetectHomepageWithOptions(ctx context.Context, rawURL string, opts HomepageOptions) (*HomepageResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	page := crawlweb.AnalyzeWebsite(rawURL, strings.HasPrefix(strings.ToLower(rawURL), "https://"))
	if page.Http.StatusCode == 0 || page.Http.Body == "" {
		return nil, errors.New("homepage not reachable")
	}
	body := achieve.SanitizeUTF8(page.Http.Body)
	if opts.MaxBodyBytes > 0 && len(body) > opts.MaxBodyBytes {
		body = body[:opts.MaxBodyBytes]
	}
	headerMap := ""
	if opts.IncludeHeaders {
		headerMap = buildHomepageHeaderMap(page.Http.StatusCode, page.Http.ResponseHeaders)
	}
	return &HomepageResult{
		URL:         rawURL,
		Title:       achieve.SanitizeUTF8(page.Http.Title),
		HTMLHash:    achieve.SanitizeUTF8(page.Http.HTMLHash),
		FaviconHash: achieve.SanitizeUTF8(page.Http.Favicon.Hash),
		ICP:         achieve.SanitizeUTF8(page.Http.ICP),
		Response: HomepageResponse{
			HeaderMap: headerMap,
			Header: HomepageResponseHeader{
				StatusCode:    page.Http.StatusCode,
				ContentLength: page.Http.ContentLength,
				ContentType:   achieve.SanitizeUTF8(page.Http.ContentType),
				Server:        achieve.SanitizeUTF8(page.Http.Server),
				RedirectChain: sanitizeStringSlice(page.Http.RedirectChain),
			},
			Body: body,
		},
	}, nil
}

// ScanDirectories 对单个 URL 执行目录爆破，并返回独立的目录爆破结果模型。
// 它不会复用 PortResult，避免端口扫描结果混入 Web/目录字段。
func (s *Scanner) ScanDirectories(ctx context.Context, rawURL string, opts DirBruteOptions) (*DirResult, error) {
	host, port, err := parseScanURL(rawURL)
	if err != nil {
		return nil, err
	}
	resolvedIP, err := resolveTarget(host)
	if err != nil {
		return nil, err
	}
	page, err := s.DetectHomepage(ctx, rawURL)
	if err != nil {
		return nil, err
	}
	return &DirResult{
		Target:     host,
		ResolvedIP: resolvedIP,
		Port:       port,
		Homepage:   page,
		Paths:      runDirBrute(*page, &opts),
	}, nil
}

// scanTCPPort 执行单个 TCP 端口的完整探测流程：
// 1) 先做 TCP 建连，失败则认为端口未开放
// 2) 建连成功后尝试申请“指纹识别令牌”
// 3) 拿到令牌则继续做 banner / 协议 / 证书等服务识别
//
// 端口扫描结果只保留端口资产字段，不再混入首页和目录爆破数据。
// 当令牌耗尽时，端口仍会被标记为 open，但不会继续做深度识别。
func (s *Scanner) scanTCPPort(
	targetHost string,
	resolvedIP string,
	port int,
	timeout time.Duration,
	fingerprintSlots chan struct{},
	fingerprintedCount *int32,
) PortResult {
	result := PortResult{Port: port}
	address := net.JoinHostPort(resolvedIP, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return result
	}
	defer conn.Close()

	// 仅允许前 N 个开放端口进入指纹识别，避免全开端口目标拖慢整体扫描。
	if fingerprintSlots != nil {
		select {
		case <-fingerprintSlots:
		default:
			result.Open = true
			result.Service = "open"
			return result
		}
	}
	// 能走到这里说明该开放端口获得了深度识别资格。
	atomic.AddInt32(fingerprintedCount, 1)

	banner, subject, dns, serviceName, version, _ := detectTCPServiceWithBudget(
		resolvedIP,
		targetHost,
		port,
		conn,
		s.opts.DisableWeakPassword,
		timeout,
	)

	result.Open = true
	result.Service = strings.TrimSuffix(serviceName, "?")
	if result.Service == "" {
		result.Service = "unknown"
	}
	result.Version = achieve.SanitizeUTF8(version)
	result.Banner = achieve.SanitizeUTF8(banner)
	result.Subject = achieve.SanitizeUTF8(subject)
	if dns != "" {
		result.DNSNames = splitAndCleanDNS(dns)
	}

	return result
}

func detectTCPServiceWithBudget(
	ip string,
	targetHost string,
	port int,
	conn net.Conn,
	disableWeakPassword bool,
	baseTimeout time.Duration,
) (banner, subject, dns, serviceName, version string, timedOut bool) {
	// 将底层较慢的协议识别放到 goroutine 中执行，
	// 外层通过 time.After 控制最大等待时间，避免单端口探测无限挂起。
	type detectResult struct {
		banner      string
		subject     string
		dns         string
		serviceName string
		version     string
	}

	resultCh := make(chan detectResult, 1)
	go func() {
		buf := make([]byte, 4096)
		b, s, d, svc, ver, _ := tcpservices.TcpPortServer(ip, targetHost, port, buf, conn, disableWeakPassword)
		resultCh <- detectResult{
			banner:      b,
			subject:     s,
			dns:         d,
			serviceName: svc,
			version:     ver,
		}
	}()

	// 指纹识别超时预算比普通 TCP 建连更宽松，因为协议交互往往需要多轮读写。
	// 同时设置一个最小值，避免 baseTimeout 过小时识别阶段几乎无法完成。
	budget := baseTimeout * 5
	if budget < 8*time.Second {
		budget = 8 * time.Second
	}

	select {
	case r := <-resultCh:
		return r.banner, r.subject, r.dns, r.serviceName, r.version, false
	case <-time.After(budget):
		return "", "", "", "unknown", "", true
	}
}

// scanUDPPort 基于 UDP 探针与匹配规则做服务识别。
// UDP 不像 TCP 那样有稳定的建连语义，因此这里只要探针有有效响应，就视为开放并输出识别结果。
func (s *Scanner) scanUDPPort(_ string, resolvedIP string, port int, timeout time.Duration) PortResult {
	result := PortResult{Port: port}
	address := net.JoinHostPort(resolvedIP, strconv.Itoa(port))
	conn, err := net.DialTimeout("udp", address, timeout)
	if err != nil {
		return result
	}
	defer conn.Close()

	buf := make([]byte, 4096)
	banner, subject, dns, serviceName, version := updservices.UcpPortServer(resolvedIP, port, buf, conn)
	if banner == "" && serviceName == "" {
		return result
	}

	result.Open = true
	result.Service = strings.TrimSuffix(serviceName, "?")
	if result.Service == "" {
		result.Service = "unknown"
	}
	result.Version = achieve.SanitizeUTF8(version)
	result.Banner = achieve.SanitizeUTF8(banner)
	result.Subject = achieve.SanitizeUTF8(subject)
	if dns != "" {
		result.DNSNames = splitAndCleanDNS(dns)
	}
	return result
}

// initAssets 从磁盘加载静态识别资产。
// 这些数据是后续 TCP/UDP 服务识别的基础，包括 nmap 风格探针和端口服务映射。
func initAssets(opts Options) error {
	logger.Init(&logger.Args{
		ServerName: "gomap",
		BasePath:   "./logs",
		Console:    opts.ConsoleLog,
		MaxBackups: 3,
		MaxSize:    50,
	})

	probesPath := opts.ProbesFile
	servicesPath := opts.ServicesFile
	if err := loadProbeAssets(probesPath); err != nil {
		return fmt.Errorf("load probes failed: %w", err)
	}
	if err := loadServiceAssets(servicesPath); err != nil {
		return fmt.Errorf("load services failed: %w", err)
	}
	probes.ExtractAllHTTPRules()
	return nil
}

// moduleRootDir 根据当前包文件路径推导仓库根目录。
func moduleRootDir() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("cannot resolve package path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..")), nil
}

// applyDefaults 填充扫描器默认参数。
// 这些值体现的是“资产探测优先”的默认策略：中等并发、较短超时、默认关闭弱口令探测、
// 指纹识别做限流、并默认开启蜜罐判定阈值。
func applyDefaults(opts *Options) {
	if opts.PortConcurrency <= 0 {
		opts.PortConcurrency = 200
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Second
	}
	if !opts.DisableWeakPassword {
		opts.DisableWeakPassword = true
	}
	if opts.MaxFingerprintPorts <= 0 {
		opts.MaxFingerprintPorts = 50
	}
	if opts.HoneypotOpenThreshold <= 0 {
		opts.HoneypotOpenThreshold = 100
	}
	if opts.HoneypotOpenRatio <= 0 {
		opts.HoneypotOpenRatio = 0.85
	}
}

func getPortRateLimiter(rate int) *portRateLimiter {
	if rate <= 0 {
		return nil
	}
	portLimiterMu.Lock()
	defer portLimiterMu.Unlock()

	if limiter, ok := portLimiterByRate[rate]; ok {
		return limiter
	}

	interval := time.Second / time.Duration(rate)
	if interval <= 0 {
		interval = time.Nanosecond
	}
	limiter := &portRateLimiter{ticker: time.NewTicker(interval)}
	portLimiterByRate[rate] = limiter
	return limiter
}

func waitPortRateLimit(ctx context.Context, limiter *portRateLimiter) error {
	if limiter == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-limiter.ticker.C:
		return nil
	}
}

// resolveTarget 将域名解析为 IP，优先返回 IPv4。
func resolveTarget(target string) (string, error) {
	if ip := net.ParseIP(target); ip != nil {
		return target, nil
	}
	ips, err := net.LookupIP(target)
	if err != nil {
		return "", fmt.Errorf("resolve target failed: %w", err)
	}
	if len(ips) == 0 {
		return "", errors.New("no IP resolved")
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return ips[0].String(), nil
}

// normalizePorts 合并显式端口与范围表达式，过滤非法端口并去重。
// 例如 Ports=[80,443] + PortSpec="80,8000-8002" 最终会得到有序唯一集合。
func normalizePorts(ports []int, spec string) ([]int, error) {
	if len(ports) == 0 && strings.TrimSpace(spec) == "" {
		return []int{80, 443}, nil
	}
	collected := make([]int, 0, len(ports)+8)
	collected = append(collected, ports...)
	if strings.TrimSpace(spec) != "" {
		p, err := parsePortSpec(spec)
		if err != nil {
			return nil, err
		}
		collected = append(collected, p...)
	}
	seen := make(map[int]struct{}, len(collected))
	out := make([]int, 0, len(collected))
	for _, p := range collected {
		if p < 1 || p > 65535 {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

// parsePortSpec 解析如 "80,443,1-1024" 的端口表达式。
func parsePortSpec(spec string) ([]int, error) {
	segments := strings.Split(spec, ",")
	ports := make([]int, 0, len(segments))
	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		if strings.Contains(segment, "-") {
			parts := strings.Split(segment, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", segment)
			}
			start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port: %s", segment)
			}
			end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port: %s", segment)
			}
			if start > end {
				start, end = end, start
			}
			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
			continue
		}
		p, err := strconv.Atoi(segment)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", segment)
		}
		ports = append(ports, p)
	}
	return ports, nil
}

// runDirBrute 执行可选的字典路径探测，并对相似结果去重。
// 这里的“去重”主要依赖首页 HTMLHash：如果某个路径返回内容与首页完全一致，
// 通常意味着是统一跳转页/兜底页，不作为有效目录结果返回。
func runDirBrute(home HomepageResult, opts *DirBruteOptions) []PathResult {
	dictFile, err := resolveDictFile(opts)
	var paths []string
	if err == nil && dictFile != "" {
		paths, err = readDictLines(dictFile, opts.MaxPaths)
	}
	if err != nil || len(paths) == 0 {
		paths, err = readBuiltinDictLines(opts.Level, opts.MaxPaths)
	}
	if err != nil || len(paths) == 0 {
		return nil
	}

	parsed, err := url.Parse(home.URL)
	if err != nil {
		return nil
	}
	base := strings.TrimRight(parsed.String(), "/")
	isHTTPS := strings.EqualFold(parsed.Scheme, "https")

	workerCount := opts.Concurrency
	if workerCount <= 0 {
		workerCount = 50
	}
	type task struct {
		path string
	}
	tasks := make(chan task, len(paths))
	results := make(chan PathResult, len(paths))
	var wg sync.WaitGroup

	// 目录爆破同样采用 worker pool，避免一次性为所有路径创建 goroutine。
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range tasks {
				targetURL := base + "/" + strings.TrimLeft(t.path, "/")
				page := crawlweb.AnalyzeWebsite(targetURL, isHTTPS)
				if page.Http.StatusCode == 0 || page.Http.StatusCode == 404 || page.Http.Body == "" {
					continue
				}
				if page.Http.HTMLHash != "" && page.Http.HTMLHash == home.HTMLHash {
					continue
				}
				results <- PathResult{
					URL:           targetURL,
					Title:         achieve.SanitizeUTF8(page.Http.Title),
					StatusCode:    page.Http.StatusCode,
					ContentLength: page.Http.ContentLength,
					HTMLHash:      achieve.SanitizeUTF8(page.Http.HTMLHash),
				}
			}
		}()
	}

	for _, p := range paths {
		tasks <- task{path: p}
	}
	close(tasks)
	wg.Wait()
	close(results)

	out := make([]PathResult, 0, len(results))
	seen := make(map[string]struct{})
	for item := range results {
		key := item.URL + "|" + item.HTMLHash
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].StatusCode == out[j].StatusCode {
			return out[i].URL < out[j].URL
		}
		return out[i].StatusCode < out[j].StatusCode
	})
	return out
}

func buildHomepageHeaderMap(statusCode int, headers map[string][]string) string {
	if len(headers) == 0 && statusCode == 0 {
		return ""
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var builder strings.Builder
	if statusCode > 0 {
		builder.WriteString(fmt.Sprintf("HTTP %d\n", statusCode))
	}
	for _, key := range keys {
		values := headers[key]
		for _, value := range values {
			builder.WriteString(key)
			builder.WriteString(": ")
			builder.WriteString(achieve.SanitizeUTF8(value))
			builder.WriteByte('\n')
		}
	}
	return strings.TrimRight(builder.String(), "\n")
}

// resolveDictFile 将爆破级别映射到内置字典文件，或使用自定义字典文件。
func resolveDictFile(opts *DirBruteOptions) (string, error) {
	if opts == nil {
		return "", errors.New("dir brute opts is nil")
	}
	if strings.TrimSpace(opts.CustomDictFile) != "" {
		return opts.CustomDictFile, nil
	}
	level := opts.Level
	if level == "" {
		level = DirBruteSimple
	}
	root, err := moduleRootDir()
	if err == nil {
		var name string
		switch level {
		case DirBruteSimple:
			name = "dict-simple.txt"
		case DirBruteNormal:
			name = "dict-normal.txt"
		case DirBruteDiff:
			name = "dict-diff.txt"
		default:
			return "", fmt.Errorf("unsupported dir brute level: %s", level)
		}
		path := filepath.Join(root, "app", name)
		if _, statErr := os.Stat(path); statErr == nil {
			return path, nil
		}
	}
	return "", os.ErrNotExist
}

// readDictLines 读取字典行，支持按 max 限制最大加载条数。
func readDictLines(path string, max int) ([]string, error) {
	if path == "" {
		return nil, os.ErrNotExist
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := make([]string, 0, 1024)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
		if max > 0 && len(out) >= max {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func loadProbeAssets(path string) error {
	if strings.TrimSpace(path) != "" {
		return probes.ProbesMatchFromFile(path)
	}
	if root, err := moduleRootDir(); err == nil {
		candidate := filepath.Join(root, "app", "gomap-service-probes")
		if _, statErr := os.Stat(candidate); statErr == nil {
			return probes.ProbesMatchFromFile(candidate)
		}
	}
	data, err := appassets.ServiceProbes()
	if err != nil {
		return err
	}
	return probes.ProbesMatchFromBytes(data, "embedded app/gomap-service-probes")
}

func loadServiceAssets(path string) error {
	if strings.TrimSpace(path) != "" {
		return service.ServiceStorageFromFile(path)
	}
	if root, err := moduleRootDir(); err == nil {
		candidate := filepath.Join(root, "app", "gomap-services")
		if _, statErr := os.Stat(candidate); statErr == nil {
			return service.ServiceStorageFromFile(candidate)
		}
	}
	data, err := appassets.Services()
	if err != nil {
		return err
	}
	return service.ServiceStorageFromBytes(data, "embedded app/gomap-services")
}

func readBuiltinDictLines(level DirBruteLevel, max int) ([]string, error) {
	if level == "" {
		level = DirBruteSimple
	}
	data, err := appassets.Dict(string(level))
	if err != nil {
		return nil, err
	}

	out := make([]string, 0, 1024)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
		if max > 0 && len(out) >= max {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// splitAndCleanDNS 将逗号分隔的 DNS 名称解析为清洗后的切片。
func splitAndCleanDNS(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, item := range parts {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out = append(out, achieve.SanitizeUTF8(item))
	}
	return out
}

func sanitizeStringSlice(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = achieve.SanitizeUTF8(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		out = append(out, item)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeTargets(targets []string) []string {
	if len(targets) == 0 {
		return nil
	}

	out := make([]string, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		out = append(out, target)
	}
	return out
}

func shuffleBatchJobs(jobs []batchJob) {
	if len(jobs) <= 1 {
		return
	}
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	rng.Shuffle(len(jobs), func(i, j int) {
		jobs[i], jobs[j] = jobs[j], jobs[i]
	})
}

func finalizeBatchTargetResult(targetCtx *batchTargetContext, honeypotOpenThreshold int, honeypotOpenRatio float64) *ScanResult {
	targetCtx.mu.Lock()
	collected := make([]PortResult, len(targetCtx.collected))
	copy(collected, targetCtx.collected)
	targetCtx.mu.Unlock()

	sort.Slice(collected, func(i, j int) bool { return collected[i].Port < collected[j].Port })

	openPorts := 0
	final := make([]PortResult, 0, len(collected))
	for _, r := range collected {
		if !r.Open {
			continue
		}
		openPorts++
		final = append(final, r)
	}

	fingerprintedOpenPorts := int(atomic.LoadInt32(&targetCtx.fingerprintedCount))
	skippedFingerprintPorts := openPorts - fingerprintedOpenPorts
	if skippedFingerprintPorts < 0 {
		skippedFingerprintPorts = 0
	}

	suspectedHoneypot := false
	honeypotReason := ""
	if targetCtx.protocol == ProtocolTCP && len(collected) > 0 {
		openRatio := float64(openPorts) / float64(len(collected))
		if openPorts >= honeypotOpenThreshold && openRatio >= honeypotOpenRatio {
			suspectedHoneypot = true
			honeypotReason = fmt.Sprintf(
				"open ports=%d/%d(%.2f%%) >= threshold=%d and ratio=%.2f%%",
				openPorts,
				len(collected),
				openRatio*100,
				honeypotOpenThreshold,
				honeypotOpenRatio*100,
			)
		}
	}

	return &ScanResult{
		Target:     targetCtx.target,
		ResolvedIP: targetCtx.resolvedIP,
		Protocol:   targetCtx.protocol,
		Meta: ScanMeta{
			OpenPorts:               openPorts,
			FingerprintedOpenPorts:  fingerprintedOpenPorts,
			SkippedFingerprintPorts: skippedFingerprintPorts,
			SuspectedHoneypot:       suspectedHoneypot,
			HoneypotReason:          honeypotReason,
		},
		Ports: final,
	}
}

func parseScanURL(raw string) (string, int, error) {
	if strings.TrimSpace(raw) == "" {
		return "", 0, errors.New("url is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", 0, errors.New("invalid url")
	}
	host := u.Hostname()
	if host == "" {
		return "", 0, errors.New("missing host in url")
	}
	if p := u.Port(); p != "" {
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return "", 0, errors.New("invalid url port")
		}
		return host, port, nil
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return host, 443, nil
	case "http":
		return host, 80, nil
	default:
		return "", 0, errors.New("url scheme must be http or https")
	}
}
