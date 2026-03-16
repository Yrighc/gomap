package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"gomap/pkg/assetprobe"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

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

func runPort(args []string) {
	fs := flag.NewFlagSet("port", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Println("用法: gomap port [options]")
		fmt.Println()
		fmt.Println("必选参数:")
		fmt.Println("  -target string    扫描目标 IP/域名（与 -ips 二选一，至少提供一个）")
		fmt.Println("  -ips string       多目标，逗号分隔（与 -target 二选一，至少提供一个）")
		fmt.Println()
		fmt.Println("可选参数:")
		fmt.Println("  -ports string     端口表达式，默认: 80,443")
		fmt.Println("  -proto string     扫描协议 tcp|udp，默认: tcp")
		fmt.Println("  -rate int         并发数，默认: 200")
		fmt.Println("  -timeout int      超时秒数，默认: 2")
		fmt.Println("  -max-fp int       最多做服务识别的开放端口数，默认: 50")
		fmt.Println("  -v                控制台实时打印日志（同时保留 logs 文件）")
		fmt.Println()
		fmt.Println("选项:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("示例:")
		fmt.Println("  gomap port -target example.com -ports 80,443,1-1024")
	}
	target := fs.String("target", "", "扫描目标 IP 或域名")
	ips := fs.String("ips", "", "兼容参数：多个目标用逗号分隔")
	ports := fs.String("ports", "80,443", "端口表达式，例如 80,443,1-1024")
	proto := fs.String("proto", "tcp", "扫描协议: tcp|udp")
	rate := fs.Int("rate", 200, "并发数")
	timeout := fs.Int("timeout", 2, "超时秒数")
	maxFingerprintPorts := fs.Int("max-fp", 50, "最多做服务识别的开放端口数")
	maxFingerprintPortsLong := fs.Int("max-fingerprint-ports", 50, "最多做服务识别的开放端口数")
	verbose := fs.Bool("v", false, "控制台实时打印日志（同时保留 logs 文件）")
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

	scanner, err := assetprobe.NewScanner(assetprobe.Options{
		Concurrency:    *rate,
		Timeout:        time.Duration(*timeout) * time.Second,
		DetectHomepage: false,
		ConsoleLog:     *verbose,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	protocol := assetprobe.ProtocolTCP
	if strings.EqualFold(*proto, "udp") {
		protocol = assetprobe.ProtocolUDP
	}

	for _, t := range targets {
		finalMaxFingerprintPorts := *maxFingerprintPorts
		if *maxFingerprintPortsLong != 50 {
			finalMaxFingerprintPorts = *maxFingerprintPortsLong
		}
		res, err := scanner.Scan(context.Background(), assetprobe.ScanRequest{
			Target:              t,
			PortSpec:            *ports,
			Protocol:            protocol,
			MaxFingerprintPorts: finalMaxFingerprintPorts,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan %s failed: %v\n", t, err)
			continue
		}
		output, _ := res.ToJSON(true)
		fmt.Println(string(output))
	}
}

func runWeb(args []string) {
	fs := flag.NewFlagSet("web", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Println("用法: gomap web [options]")
		fmt.Println()
		fmt.Println("必选参数:")
		fmt.Println("  -url string       要识别的站点 URL，例如 https://example.com")
		fmt.Println()
		fmt.Println("可选参数:")
		fmt.Println("  -rate int         并发数（影响 scanner 初始化），默认: 100")
		fmt.Println("  -timeout int      超时秒数，默认: 5")
		fmt.Println("  -v                控制台实时打印日志（同时保留 logs 文件）")
		fmt.Println()
		fmt.Println("选项:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("示例:")
		fmt.Println("  gomap web -url https://example.com")
	}
	rawURL := fs.String("url", "", "要识别的站点 URL，例如 https://example.com")
	rate := fs.Int("rate", 100, "并发数（保留参数，影响 scanner 初始化）")
	timeout := fs.Int("timeout", 5, "超时秒数")
	verbose := fs.Bool("v", false, "控制台实时打印日志（同时保留 logs 文件）")
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

	scanner, err := assetprobe.NewScanner(assetprobe.Options{
		Concurrency:    *rate,
		Timeout:        time.Duration(*timeout) * time.Second,
		DetectHomepage: true,
		ConsoleLog:     *verbose,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	page, err := scanner.DetectHomepage(context.Background(), *rawURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	output, _ := json.MarshalIndent(page, "", "  ")
	fmt.Println(string(output))
}

func runDir(args []string) {
	fs := flag.NewFlagSet("dir", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Println("用法: gomap dir [options]")
		fmt.Println()
		fmt.Println("必选参数:")
		fmt.Println("  -url string       目录爆破目标 URL，例如 https://example.com")
		fmt.Println()
		fmt.Println("可选参数:")
		fmt.Println("  -dict string      爆破字典 simple|normal|diff，默认: simple")
		fmt.Println("  -dict-file string 自定义爆破字典路径")
		fmt.Println("  -dict-max int     最大字典行数，默认: 0（不限制）")
		fmt.Println("  -dict-concurrency int 目录爆破并发，默认: 50")
		fmt.Println("  -rate int         并发数，默认: 200")
		fmt.Println("  -timeout int      超时秒数，默认: 3")
		fmt.Println("  -v                控制台实时打印日志（同时保留 logs 文件）")
		fmt.Println()
		fmt.Println("选项:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("示例:")
		fmt.Println("  gomap dir -url https://example.com -dict normal -dict-max 500")
	}
	rawURL := fs.String("url", "", "目录爆破目标 URL，例如 https://example.com")
	rate := fs.Int("rate", 200, "并发数")
	timeout := fs.Int("timeout", 3, "超时秒数")
	dictLevel := fs.String("dict", "simple", "目录爆破字典级别: simple|normal|diff")
	dictFile := fs.String("dict-file", "", "自定义目录爆破字典文件路径")
	dictMax := fs.Int("dict-max", 0, "目录爆破最多加载路径条数，0 表示不限制")
	dictConcurrency := fs.Int("dict-concurrency", 50, "目录爆破并发数")
	verbose := fs.Bool("v", false, "控制台实时打印日志（同时保留 logs 文件）")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	target, port, err := parseURLTarget(*rawURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	scanner, err := assetprobe.NewScanner(assetprobe.Options{
		Concurrency:    *rate,
		Timeout:        time.Duration(*timeout) * time.Second,
		DetectHomepage: true,
		ConsoleLog:     *verbose,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	enableHomepage := true
	res, err := scanner.Scan(context.Background(), assetprobe.ScanRequest{
		Target:         target,
		Ports:          []int{port},
		Protocol:       assetprobe.ProtocolTCP,
		DetectHomepage: &enableHomepage,
		DirBrute: &assetprobe.DirBruteOptions{
			Enable:         true,
			Level:          assetprobe.DirBruteLevel(strings.ToLower(*dictLevel)),
			CustomDictFile: *dictFile,
			MaxPaths:       *dictMax,
			Concurrency:    *dictConcurrency,
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	output, _ := res.ToJSON(true)
	fmt.Println(string(output))
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
	fmt.Println()
	fmt.Println("示例:")
	fmt.Println("  gomap port -target example.com -ports 80,443,1-1024")
	fmt.Println("  gomap web -url https://example.com")
	fmt.Println("  gomap dir -url https://example.com -dict normal -dict-max 500")
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
