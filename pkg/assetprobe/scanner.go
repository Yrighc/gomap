package assetprobe

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gomap/config/logger"
	"gomap/config/probes"
	"gomap/config/service"
	"gomap/internal/achieve"
	"gomap/internal/crawlweb"
	"gomap/internal/tcpservices"
	"gomap/internal/updservices"
)

var (
	initOnce sync.Once
	initErr  error
)

type Scanner struct {
	opts Options
}

// NewScanner 初始化探测所需资源（nmap 探针与服务字典），
// 每个进程只加载一次，并返回可复用的扫描器实例。
func NewScanner(opts Options) (*Scanner, error) {
	applyDefaults(&opts)
	initOnce.Do(func() {
		initErr = initAssets(opts)
	})
	if initErr != nil {
		return nil, initErr
	}
	return &Scanner{opts: opts}, nil
}

// Scan 是主流程：
// 1) 规范化目标、端口与参数
// 2) 并发执行端口探测
// 3) 汇总并排序结果
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

	timeout := s.opts.Timeout
	if req.Timeout > 0 {
		timeout = req.Timeout
	}
	concurrency := s.opts.Concurrency
	if req.Concurrency > 0 {
		concurrency = req.Concurrency
	}
	detectHomepage := s.opts.DetectHomepage
	if req.DetectHomepage != nil {
		detectHomepage = *req.DetectHomepage
	}
	dirBrute := req.DirBrute

	jobs := make(chan int, len(ports))
	results := make(chan PortResult, len(ports))
	var wg sync.WaitGroup

	// 端口级并发 Worker 池。
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				var r PortResult
				switch req.Protocol {
				case ProtocolUDP:
					r = s.scanUDPPort(targetHost, resolvedIP, p, timeout)
				default:
					r = s.scanTCPPort(targetHost, resolvedIP, p, timeout, detectHomepage, dirBrute)
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

	final := make([]PortResult, 0, len(ports))
	for r := range results {
		final = append(final, r)
	}
	sort.Slice(final, func(i, j int) bool { return final[i].Port < final[j].Port })

	return &ScanResult{
		Target:     targetHost,
		ResolvedIP: resolvedIP,
		Protocol:   req.Protocol,
		Ports:      final,
	}, nil
}

// Probe 是单端口便捷封装，内部复用 Scan。
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
		return nil, errors.New("no probe result")
	}
	return &result.Ports[0], nil
}

// DetectHomepage 探测单个 URL，并返回标准化首页元信息。
func (s *Scanner) DetectHomepage(ctx context.Context, rawURL string) (*HomepageResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	page := crawlweb.AnalyzeWebsite(rawURL, strings.HasPrefix(strings.ToLower(rawURL), "https://"))
	if page.Http.StatusCode == 0 || page.Http.Body == "" {
		return nil, errors.New("homepage not reachable")
	}
	return &HomepageResult{
		URL:           rawURL,
		Title:         achieve.SanitizeUTF8(page.Http.Title),
		StatusCode:    page.Http.StatusCode,
		ContentLength: page.Http.ContentLength,
		Server:        achieve.SanitizeUTF8(page.Http.Server),
		HTMLHash:      achieve.SanitizeUTF8(page.Http.HTMLHash),
		FaviconHash:   achieve.SanitizeUTF8(page.Http.Favicon.Hash),
		ICP:           achieve.SanitizeUTF8(page.Http.ICP),
	}, nil
}

// scanTCPPort 执行 TCP 连接、服务识别，并按需执行首页识别和目录爆破。
func (s *Scanner) scanTCPPort(targetHost, resolvedIP string, port int, timeout time.Duration, detectHomepage bool, dirBrute *DirBruteOptions) PortResult {
	result := PortResult{Port: port}
	address := net.JoinHostPort(resolvedIP, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return result
	}
	defer conn.Close()

	buf := make([]byte, 4096)
	banner, subject, dns, serviceName, version, weak := tcpservices.TcpPortServer(resolvedIP, port, buf, conn, s.opts.DisableWeakPassword)

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
	result.WeakUser = weak.Username
	result.WeakPass = weak.Password

	if detectHomepage && shouldDetectHomepage(port, result.Service) {
		if page := detectPortHomepage(targetHost, port, result.Service); page != nil {
			if dirBrute != nil && dirBrute.Enable {
				page.Paths = runDirBrute(*page, dirBrute)
			}
			result.Homepage = page
		}
	}

	return result
}

// scanUDPPort 基于 UDP 探针与匹配规则做服务识别。
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

// initAssets 从探针文件与服务文件加载静态匹配数据。
func initAssets(opts Options) error {
	logger.Init(&logger.Args{
		ServerName: "gomap-assetprobe",
		BasePath:   "./logs",
		Console:    false,
		MaxBackups: 3,
		MaxSize:    50,
	})

	root, err := moduleRootDir()
	if err != nil {
		return err
	}
	probesPath := opts.ProbesFile
	if probesPath == "" {
		probesPath = filepath.Join(root, "app", "gomap-service-probes")
	}
	servicesPath := opts.ServicesFile
	if servicesPath == "" {
		servicesPath = filepath.Join(root, "app", "gomap-services")
	}
	if err := probes.ProbesMatchFromFile(probesPath); err != nil {
		return fmt.Errorf("load probes failed: %w", err)
	}
	if err := service.ServiceStorageFromFile(servicesPath); err != nil {
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
func applyDefaults(opts *Options) {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 200
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Second
	}
	if !opts.DisableWeakPassword {
		opts.DisableWeakPassword = true
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

// shouldDetectHomepage 将首页识别限制在常见 HTTP 类服务或端口上。
func shouldDetectHomepage(port int, service string) bool {
	s := strings.ToLower(service)
	if strings.Contains(s, "http") {
		return true
	}
	switch port {
	case 80, 443, 8080, 8443, 8000, 8888, 9443:
		return true
	default:
		return false
	}
}

// detectPortHomepage 按服务特征决定协议尝试顺序，返回首个可达首页。
func detectPortHomepage(host string, port int, service string) *HomepageResult {
	hostPort := net.JoinHostPort(host, strconv.Itoa(port))
	tryURLs := []string{}
	if strings.Contains(strings.ToLower(service), "ssl") || port == 443 || port == 8443 || port == 9443 {
		tryURLs = append(tryURLs, "https://"+hostPort, "http://"+hostPort)
	} else {
		tryURLs = append(tryURLs, "http://"+hostPort, "https://"+hostPort)
	}
	for _, u := range tryURLs {
		param := crawlweb.AnalyzeWebsite(u, strings.HasPrefix(u, "https://"))
		if param.Http.StatusCode == 0 || param.Http.Body == "" {
			continue
		}
		return &HomepageResult{
			URL:           u,
			Title:         achieve.SanitizeUTF8(param.Http.Title),
			StatusCode:    param.Http.StatusCode,
			ContentLength: param.Http.ContentLength,
			Server:        achieve.SanitizeUTF8(param.Http.Server),
			HTMLHash:      achieve.SanitizeUTF8(param.Http.HTMLHash),
			FaviconHash:   achieve.SanitizeUTF8(param.Http.Favicon.Hash),
			ICP:           achieve.SanitizeUTF8(param.Http.ICP),
		}
	}
	return nil
}

// runDirBrute 执行可选的字典路径探测，并对相似结果去重。
func runDirBrute(home HomepageResult, opts *DirBruteOptions) []PathResult {
	dictFile, err := resolveDictFile(opts)
	if err != nil {
		return nil
	}
	paths, err := readDictLines(dictFile, opts.MaxPaths)
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

// resolveDictFile 将爆破级别映射到内置字典文件，或使用自定义字典文件。
func resolveDictFile(opts *DirBruteOptions) (string, error) {
	if opts == nil {
		return "", errors.New("dir brute opts is nil")
	}
	if strings.TrimSpace(opts.CustomDictFile) != "" {
		return opts.CustomDictFile, nil
	}
	root, err := moduleRootDir()
	if err != nil {
		return "", err
	}
	level := opts.Level
	if level == "" {
		level = DirBruteSimple
	}
	switch level {
	case DirBruteSimple:
		return filepath.Join(root, "app", "简单.txt"), nil
	case DirBruteNormal:
		return filepath.Join(root, "app", "一般.txt"), nil
	case DirBruteDiff:
		return filepath.Join(root, "app", "复杂.txt"), nil
	default:
		return "", fmt.Errorf("unsupported dir brute level: %s", level)
	}
}

// readDictLines 读取字典行，支持按 max 限制最大加载条数。
func readDictLines(path string, max int) ([]string, error) {
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
