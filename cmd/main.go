package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/yrighc/gomap/pkg/assetprobe"
	"github.com/yrighc/gomap/pkg/secprobe"
)

const csvTimeLayout = "2006-01-02 15:04:05"

type portWithWeakOutput struct {
	Asset    *assetprobe.ScanResult `json:"asset"`
	Security *secprobe.RunResult    `json:"security"`
}

func main() {
	if len(os.Args) < 2 {
		printRootUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "port":
		runPort(os.Args[2:])
	case "web":
		runWeb(os.Args[2:])
	case "dir":
		runDir(os.Args[2:])
	case "weak":
		runWeak(os.Args[2:])
	case "help", "-h", "--help":
		printRootUsage()
	default:
		if strings.HasPrefix(os.Args[1], "-") {
			fmt.Fprintln(os.Stderr, "[兼容模式] 检测到旧参数格式，已按 port 模式执行。建议迁移为: gomap port ...")
			runPort(os.Args[1:])
			return
		}
		fmt.Fprintf(os.Stderr, "未知子命令: %s\n\n", os.Args[1])
		printRootUsage()
		os.Exit(1)
	}
}

func runWeak(args []string) {
	fs := flag.NewFlagSet("weak", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Println("用法: gomap weak [options]")
		fmt.Println()
		fmt.Println("选项:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("示例:")
		fmt.Println("  gomap weak -target example.com -ports 21,22,3306,5432,6379")
	}

	target := fs.String("target", "", "[必选，和 -ips 二选一] 扫描目标 IP 或域名")
	ips := fs.String("ips", "", "[必选，和 -target 二选一] 多个目标用逗号分隔")
	ports := fs.String("ports", "21,22,23,3306,5432,6379", "[可选] 端口表达式，例如 21,22,3306")
	protocols := fs.String("protocols", "", "[可选] 仅探测指定协议，逗号分隔")
	timeout := fs.Int("timeout", 3, "[可选] 资产发现与 secprobe 超时秒数")
	weakConcurrency := fs.Int("weak-concurrency", 10, "[可选] secprobe 并发数")
	dictDir := fs.String("dict-dir", "", "[可选] 自定义协议字典目录")
	inlineCreds := fs.String("up", "", "[可选] 内联凭证，格式 'admin : admin,root : root'")
	credFile := fs.String("upf", "", "[可选] 凭证文件，一行一个 'admin : admin'")
	stopOnSuccess := fs.Bool("stop-on-success", true, "[可选] 单目标命中后停止继续尝试")
	verbose := fs.Bool("v", false, "[可选] 控制台实时打印日志（同时保留 logs 文件）")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	targets := collectTargets(*target, *ips)
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "target 不能为空，例如: gomap weak -target example.com 或 -ips 1.1.1.1,example.com")
		os.Exit(1)
	}
	if *timeout <= 0 {
		fmt.Fprintln(os.Stderr, "timeout 必须大于 0")
		os.Exit(1)
	}
	if *weakConcurrency <= 0 {
		fmt.Fprintln(os.Stderr, "weak-concurrency 必须大于 0")
		os.Exit(1)
	}

	creds, err := collectCredentials(*inlineCreds, *credFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	discoveryTimeout := time.Duration(*timeout) * time.Second
	scanner, err := assetprobe.NewScanner(assetprobe.Options{
		Timeout:    discoveryTimeout,
		ConsoleLog: *verbose,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	batchRes, err := scanner.ScanTargets(context.Background(), targets, assetprobe.ScanCommonOptions{
		PortSpec: *ports,
		Protocol: assetprobe.ProtocolTCP,
		Timeout:  discoveryTimeout,
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "batch scan finished with error: %v\n", err)
	}

	secprobeOpts := secprobe.CredentialProbeOptions{
		Protocols:     splitComma(*protocols),
		Concurrency:   *weakConcurrency,
		Timeout:       discoveryTimeout,
		StopOnSuccess: *stopOnSuccess,
		DictDir:       strings.TrimSpace(*dictDir),
		Credentials:   creds,
	}

	candidates := make([]secprobe.SecurityCandidate, 0)
	for _, item := range batchRes.Results {
		if item.Error != "" {
			fmt.Fprintf(os.Stderr, "scan %s failed: %s\n", item.Target, item.Error)
			continue
		}
		if item.Result == nil {
			fmt.Fprintf(os.Stderr, "scan %s failed: empty result\n", item.Target)
			continue
		}
		candidates = append(candidates, secprobe.BuildCandidates(item.Result, secprobeOpts)...)
	}

	result := secprobe.Run(context.Background(), candidates, secprobeOpts)
	output, err := result.ToJSON(true)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(output))
}

func runPort(args []string) {
	fs := flag.NewFlagSet("port", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Println("用法: gomap port [options]")
		fmt.Println()
		fmt.Println("选项:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("示例:")
		fmt.Println("  gomap port -target example.com -ports 80,443,1-1024 -c 200 -rate 3000")
	}
	target := fs.String("target", "", "[必选，和 -ips 二选一] 扫描目标 IP 或域名")
	ips := fs.String("ips", "", "[必选，和 -target 二选一] 多个目标用逗号分隔")
	ports := fs.String("ports", "80,443", "[可选] 端口表达式，例如 80,443,1-1024")
	proto := fs.String("proto", "tcp", "[可选] 扫描协议: tcp|udp")
	portConcurrency := fs.Int("concurrency", 200, "[可选] 端口扫描并发数")
	portConcurrencyShort := fs.Int("c", 200, "[可选] 端口扫描并发数")
	portRateLimit := fs.Int("ratelimit", 0, "[可选] 端口扫描全局速率限制（每秒）")
	portRateLimitShort := fs.Int("rate", 0, "[可选] 端口扫描全局速率限制（每秒）")
	timeout := fs.Int("timeout", 2, "[可选] 超时秒数")
	maxFingerprintPorts := fs.Int("max-fp", 50, "[可选] 最多做服务识别的开放端口数")
	maxFingerprintPortsLong := fs.Int("max-fingerprint-ports", 50, "[可选] 最多做服务识别的开放端口数")
	honeypotOpenThreshold := fs.Int("honeypot-open-threshold", 100, "[可选] 疑似蜜罐判定最小开放端口数阈值")
	honeypotOpenRatio := fs.Float64("honeypot-open-ratio", 0.85, "[可选] 疑似蜜罐判定开放占比阈值，范围 0~1")
	enableCSV := fs.Bool("csv", false, "[可选] 将扫描结果写入 logs/port.csv")
	csvMode := fs.String("csv-mode", "append", "[可选] CSV 写入模式: append|overwrite")
	verbose := fs.Bool("v", false, "[可选] 控制台实时打印日志（同时保留 logs 文件）")
	enableWeak := fs.Bool("weak", false, "[可选] 在端口扫描后执行账号口令探测")
	weakProtocols := fs.String("weak-protocols", "", "[可选] 限定 weak 探测协议，逗号分隔")
	weakConcurrency := fs.Int("weak-concurrency", 10, "[可选] weak 探测并发数")
	weakStopOnSuccess := fs.Bool("weak-stop-on-success", true, "[可选] weak 命中后停止继续尝试")
	weakDictDir := fs.String("weak-dict-dir", "", "[可选] 自定义 weak 字典目录")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	targets := collectTargets(*target, *ips)
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "target 不能为空，例如: gomap port -target example.com 或 -ips 1.1.1.1,example.com")
		os.Exit(1)
	}
	if *honeypotOpenThreshold <= 0 {
		fmt.Fprintln(os.Stderr, "honeypot-open-threshold 必须大于 0")
		os.Exit(1)
	}
	if *honeypotOpenRatio <= 0 || *honeypotOpenRatio > 1 {
		fmt.Fprintln(os.Stderr, "honeypot-open-ratio 必须在 (0,1] 范围内，例如 0.85")
		os.Exit(1)
	}
	finalPortConcurrency := *portConcurrency
	if *portConcurrencyShort != 200 {
		finalPortConcurrency = *portConcurrencyShort
	}
	if finalPortConcurrency <= 0 {
		fmt.Fprintln(os.Stderr, "concurrency 必须大于 0")
		os.Exit(1)
	}
	finalPortRateLimit := *portRateLimit
	if *portRateLimitShort > 0 {
		finalPortRateLimit = *portRateLimitShort
	}
	if finalPortRateLimit < 0 {
		fmt.Fprintln(os.Stderr, "ratelimit 不能小于 0")
		os.Exit(1)
	}
	if *enableWeak && *weakConcurrency <= 0 {
		fmt.Fprintln(os.Stderr, "weak-concurrency 必须大于 0")
		os.Exit(1)
	}
	scanner, err := assetprobe.NewScanner(assetprobe.Options{
		PortConcurrency: finalPortConcurrency,
		PortRateLimit:   finalPortRateLimit,
		Timeout:         time.Duration(*timeout) * time.Second,
		ConsoleLog:      *verbose,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	protocol := assetprobe.ProtocolTCP
	if strings.EqualFold(*proto, "udp") {
		protocol = assetprobe.ProtocolUDP
	}

	var csvWriter *csv.Writer
	var csvFile *os.File
	if *enableCSV {
		header := []string{
			"scan_time", "target", "resolved_ip", "protocol", "port", "open", "service", "version",
			"banner", "subject", "dns_names", "open_ports",
			"fingerprinted_open_ports", "skipped_fingerprint_ports", "suspected_honeypot", "honeypot_reason",
		}
		csvFile, csvWriter, err = openCSVWriter(filepath.Join("logs", "port.csv"), *csvMode, header)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer csvFile.Close()
		defer csvWriter.Flush()
	}

	finalMaxFingerprintPorts := *maxFingerprintPorts
	if *maxFingerprintPortsLong != 50 {
		finalMaxFingerprintPorts = *maxFingerprintPortsLong
	}

	batchRes, err := scanner.ScanTargets(context.Background(), targets, assetprobe.ScanCommonOptions{
		PortSpec:              *ports,
		Protocol:              protocol,
		PortConcurrency:       finalPortConcurrency,
		PortRateLimit:         finalPortRateLimit,
		Timeout:               time.Duration(*timeout) * time.Second,
		MaxFingerprintPorts:   finalMaxFingerprintPorts,
		HoneypotOpenThreshold: *honeypotOpenThreshold,
		HoneypotOpenRatio:     *honeypotOpenRatio,
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "batch scan finished with error: %v\n", err)
	}

	for _, item := range batchRes.Results {
		if item.Error != "" {
			fmt.Fprintf(os.Stderr, "scan %s failed: %s\n", item.Target, item.Error)
			continue
		}
		res := item.Result
		if res == nil {
			fmt.Fprintf(os.Stderr, "scan %s failed: empty result\n", item.Target)
			continue
		}
		var security *secprobe.RunResult
		if *enableWeak {
			weakOpts := buildPortWeakProbeOptions(*weakProtocols, *weakConcurrency, time.Duration(*timeout)*time.Second, *weakStopOnSuccess, *weakDictDir)
			candidates := secprobe.BuildCandidates(res, weakOpts)
			weakResult := secprobe.Run(context.Background(), candidates, weakOpts)
			security = &weakResult
		}

		output, _ := marshalPortOutput(res, security, true)
		fmt.Println(string(output))

		if csvWriter != nil {
			now := time.Now().Format(csvTimeLayout)
			for _, p := range res.Ports {
				row := []string{
					now,
					res.Target,
					res.ResolvedIP,
					string(res.Protocol),
					strconv.Itoa(p.Port),
					strconv.FormatBool(p.Open),
					p.Service,
					p.Version,
					p.Banner,
					p.Subject,
					strings.Join(p.DNSNames, ";"),
					strconv.Itoa(res.Meta.OpenPorts),
					strconv.Itoa(res.Meta.FingerprintedOpenPorts),
					strconv.Itoa(res.Meta.SkippedFingerprintPorts),
					strconv.FormatBool(res.Meta.SuspectedHoneypot),
					res.Meta.HoneypotReason,
				}
				if err := csvWriter.Write(row); err != nil {
					fmt.Fprintf(os.Stderr, "写入 port.csv 失败: %v\n", err)
				}
			}
			csvWriter.Flush()
			if err := csvWriter.Error(); err != nil {
				fmt.Fprintf(os.Stderr, "刷新 port.csv 失败: %v\n", err)
			}
		}
	}
}

func runWeb(args []string) {
	fs := flag.NewFlagSet("web", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Println("用法: gomap web [options]")
		fmt.Println()
		fmt.Println("选项:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("示例:")
		fmt.Println("  gomap web -url https://example.com")
	}
	rawURL := fs.String("url", "", "[必选] 要识别的站点 URL，例如 https://example.com")
	timeout := fs.Int("timeout", 5, "[可选] 超时秒数")
	includeHeaders := fs.Bool("include-headers", false, "[可选] 返回响应头")
	maxBodyBytes := fs.Int("max-body", 0, "[可选] 返回体最大字节数，0 表示完整 body")
	enableCSV := fs.Bool("csv", false, "[可选] 将识别结果写入 logs/web.csv")
	csvMode := fs.String("csv-mode", "append", "[可选] CSV 写入模式: append|overwrite")
	verbose := fs.Bool("v", false, "[可选] 控制台实时打印日志（同时保留 logs 文件）")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	if strings.TrimSpace(*rawURL) == "" {
		fmt.Fprintln(os.Stderr, "url 不能为空，例如: gomap web -url https://example.com")
		os.Exit(1)
	}
	if *maxBodyBytes < 0 {
		fmt.Fprintln(os.Stderr, "max-body 不能小于 0")
		os.Exit(1)
	}

	scanner, err := assetprobe.NewScanner(assetprobe.Options{
		Timeout:    time.Duration(*timeout) * time.Second,
		ConsoleLog: *verbose,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	page, err := scanner.DetectHomepageWithOptions(context.Background(), *rawURL, assetprobe.HomepageOptions{
		IncludeHeaders: *includeHeaders,
		MaxBodyBytes:   *maxBodyBytes,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	output, _ := json.MarshalIndent(page, "", "  ")
	fmt.Println(string(output))

	if *enableCSV {
		header := []string{"scan_time", "url", "title", "status_code", "content_length", "server", "html_hash", "favicon_hash", "icp"}
		csvFile, csvWriter, err := openCSVWriter(filepath.Join("logs", "web.csv"), *csvMode, header)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer csvFile.Close()

		row := []string{
			time.Now().Format(csvTimeLayout),
			page.URL,
			page.Title,
			strconv.Itoa(page.Response.Header.StatusCode),
			strconv.FormatInt(page.Response.Header.ContentLength, 10),
			page.Response.Header.Server,
			page.HTMLHash,
			page.FaviconHash,
			page.ICP,
		}
		if err := csvWriter.Write(row); err != nil {
			fmt.Fprintf(os.Stderr, "写入 web.csv 失败: %v\n", err)
		}
		csvWriter.Flush()
		if err := csvWriter.Error(); err != nil {
			fmt.Fprintf(os.Stderr, "刷新 web.csv 失败: %v\n", err)
		}
	}
}

func runDir(args []string) {
	fs := flag.NewFlagSet("dir", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Println("用法: gomap dir [options]")
		fmt.Println()
		fmt.Println("选项:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("示例:")
		fmt.Println("  gomap dir -url https://example.com -dict normal -dict-max 500")
	}
	rawURL := fs.String("url", "", "[必选] 目录爆破目标 URL，例如 https://example.com")
	timeout := fs.Int("timeout", 3, "[可选] 超时秒数")
	dictLevel := fs.String("dict", "simple", "[可选] 目录爆破字典级别: simple|normal|diff")
	dictFile := fs.String("dict-file", "", "[可选] 自定义目录爆破字典文件路径")
	dictMax := fs.Int("dict-max", 0, "[可选] 目录爆破最多加载路径条数，0 表示不限制")
	dictConcurrency := fs.Int("dict-concurrency", 50, "[可选] 目录爆破并发数")
	enableCSV := fs.Bool("csv", false, "[可选] 将目录爆破结果写入 logs/dir.csv")
	csvMode := fs.String("csv-mode", "append", "[可选] CSV 写入模式: append|overwrite")
	verbose := fs.Bool("v", false, "[可选] 控制台实时打印日志（同时保留 logs 文件）")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	scanner, err := assetprobe.NewScanner(assetprobe.Options{
		Timeout:    time.Duration(*timeout) * time.Second,
		ConsoleLog: *verbose,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	res, err := scanner.ScanDirectories(context.Background(), *rawURL, assetprobe.DirBruteOptions{
		Enable:         true,
		Level:          assetprobe.DirBruteLevel(strings.ToLower(*dictLevel)),
		CustomDictFile: *dictFile,
		MaxPaths:       *dictMax,
		Concurrency:    *dictConcurrency,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	output, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(output))

	if *enableCSV {
		header := []string{
			"scan_time", "target", "resolved_ip", "port", "homepage_url", "homepage_title",
			"homepage_status_code", "path_url", "path_title", "path_status_code", "path_content_length", "path_html_hash",
		}
		csvFile, csvWriter, err := openCSVWriter(filepath.Join("logs", "dir.csv"), *csvMode, header)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer csvFile.Close()

		now := time.Now().Format(csvTimeLayout)
		if res.Homepage == nil {
			row := []string{
				now, res.Target, res.ResolvedIP, strconv.Itoa(res.Port),
				"", "", "", "", "", "", "", "",
			}
			if err := csvWriter.Write(row); err != nil {
				fmt.Fprintf(os.Stderr, "写入 dir.csv 失败: %v\n", err)
			}
		} else if len(res.Paths) == 0 {
			row := []string{
				now,
				res.Target,
				res.ResolvedIP,
				strconv.Itoa(res.Port),
				res.Homepage.URL,
				res.Homepage.Title,
				strconv.Itoa(res.Homepage.Response.Header.StatusCode),
				"", "", "", "", "",
			}
			if err := csvWriter.Write(row); err != nil {
				fmt.Fprintf(os.Stderr, "写入 dir.csv 失败: %v\n", err)
			}
		} else {
			for _, path := range res.Paths {
				row := []string{
					now,
					res.Target,
					res.ResolvedIP,
					strconv.Itoa(res.Port),
					res.Homepage.URL,
					res.Homepage.Title,
					strconv.Itoa(res.Homepage.Response.Header.StatusCode),
					path.URL,
					path.Title,
					strconv.Itoa(path.StatusCode),
					strconv.FormatInt(path.ContentLength, 10),
					path.HTMLHash,
				}
				if err := csvWriter.Write(row); err != nil {
					fmt.Fprintf(os.Stderr, "写入 dir.csv 失败: %v\n", err)
				}
			}
		}
		csvWriter.Flush()
		if err := csvWriter.Error(); err != nil {
			fmt.Fprintf(os.Stderr, "刷新 dir.csv 失败: %v\n", err)
		}
	}
}

// openCSVWriter 按模式打开 CSV 文件；append 模式下仅在新文件时写表头。
func openCSVWriter(path, mode string, header []string) (*os.File, *csv.Writer, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "append"
	}
	if mode != "append" && mode != "overwrite" {
		return nil, nil, fmt.Errorf("无效 csv-mode: %s（仅支持 append|overwrite）", mode)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, nil, fmt.Errorf("创建日志目录失败: %w", err)
	}

	fileFlags := os.O_CREATE | os.O_WRONLY
	writeHeader := false
	switch mode {
	case "overwrite":
		fileFlags |= os.O_TRUNC
		writeHeader = true
	default:
		fileFlags |= os.O_APPEND
		if fi, err := os.Stat(path); errors.Is(err, os.ErrNotExist) || (err == nil && fi.Size() == 0) {
			writeHeader = true
		} else if err != nil {
			return nil, nil, fmt.Errorf("检查 CSV 文件失败: %w", err)
		}
	}

	f, err := os.OpenFile(path, fileFlags, 0o644)
	if err != nil {
		return nil, nil, fmt.Errorf("打开 CSV 文件失败: %w", err)
	}
	w := csv.NewWriter(f)
	if writeHeader {
		if err := w.Write(header); err != nil {
			f.Close()
			return nil, nil, fmt.Errorf("写入 CSV 表头失败: %w", err)
		}
		w.Flush()
		if err := w.Error(); err != nil {
			f.Close()
			return nil, nil, fmt.Errorf("刷新 CSV 表头失败: %w", err)
		}
	}
	return f, w, nil
}

func parseURLTarget(raw string) (string, int, error) {
	if strings.TrimSpace(raw) == "" {
		return "", 0, errors.New("url 不能为空，例如: gomap dir -url https://example.com")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", 0, errors.New("无效 URL，请使用完整地址，例如: https://example.com")
	}
	host := u.Hostname()
	if host == "" {
		return "", 0, errors.New("URL 中缺少 host")
	}

	if p := u.Port(); p != "" {
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return "", 0, errors.New("URL 端口无效")
		}
		return host, port, nil
	}

	switch strings.ToLower(u.Scheme) {
	case "https":
		return host, 443, nil
	case "http":
		return host, 80, nil
	default:
		return "", 0, errors.New("URL scheme 必须是 http 或 https")
	}
}

func printRootUsage() {
	fmt.Println("GoMap 资产探测 CLI")
	fmt.Println()
	fmt.Println("用法:")
	fmt.Println("  gomap <command> [options]")
	fmt.Println()
	fmt.Println("命令:")
	fmt.Println("  port   端口扫描与服务识别")
	fmt.Println("  web    首页识别")
	fmt.Println("  dir    目录爆破")
	fmt.Println("  weak   协议账号口令探测")
	fmt.Println()
	fmt.Println("示例:")
	fmt.Println("  gomap port -target example.com -ports 80,443,1-1024")
	fmt.Println("  gomap web -url https://example.com")
	fmt.Println("  gomap dir -url https://example.com -dict normal -dict-max 500")
	fmt.Println("  gomap weak -target example.com -ports 21,22,3306,5432,6379")
}

func collectTargets(target, ips string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, 8)
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	add(target)
	for _, item := range strings.Split(ips, ",") {
		add(item)
	}
	return out
}

func collectCredentials(inline, file string) ([]secprobe.Credential, error) {
	hasInline := strings.TrimSpace(inline) != ""
	hasFile := strings.TrimSpace(file) != ""
	lines := make([]string, 0)
	if hasInline {
		lines = append(lines, splitComma(inline)...)
	}
	if hasFile {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		lines = append(lines, strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")...)
	}

	out := make([]secprobe.Credential, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		username, password, ok := parseCredentialPair(line)
		if !ok {
			return nil, fmt.Errorf("invalid credential pair %q, expected 'username : password'", line)
		}
		out = append(out, secprobe.Credential{
			Username: username,
			Password: password,
		})
	}
	if (hasInline || hasFile) && len(out) == 0 {
		return nil, errors.New("no valid explicit credentials found")
	}
	return out, nil
}

func parseCredentialPair(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", false
	}
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	username := strings.TrimSpace(parts[0])
	password := strings.TrimSpace(parts[1])
	if username == "" || password == "" {
		return "", "", false
	}
	return username, password, true
}

func splitComma(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func buildPortWeakProbeOptions(protocols string, concurrency int, timeout time.Duration, stopOnSuccess bool, dictDir string) secprobe.CredentialProbeOptions {
	return secprobe.CredentialProbeOptions{
		Protocols:     splitComma(protocols),
		Concurrency:   concurrency,
		Timeout:       timeout,
		StopOnSuccess: stopOnSuccess,
		DictDir:       strings.TrimSpace(dictDir),
	}
}

func marshalPortOutput(asset *assetprobe.ScanResult, security *secprobe.RunResult, pretty bool) ([]byte, error) {
	if security == nil {
		return assetprobe.MarshalJSON(asset, pretty)
	}
	return assetprobe.MarshalJSON(portWithWeakOutput{
		Asset:    asset,
		Security: security,
	}, pretty)
}
