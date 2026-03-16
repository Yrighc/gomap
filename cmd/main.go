package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"gomap/pkg/assetprobe"
	"os"
	"strings"
	"time"
)

func main() {
	target := flag.String("target", "", "扫描目标 IP 或域名")
	ips := flag.String("ips", "", "兼容参数：多个目标用逗号分隔")
	ports := flag.String("ports", "80,443", "端口表达式，例如 80,443,1-1024")
	proto := flag.String("proto", "tcp", "扫描协议: tcp|udp")
	rate := flag.Int("rate", 200, "并发数")
	timeout := flag.Int("timeout", 2, "超时秒数")
	homepage := flag.Bool("homepage", true, "是否进行首页识别")
	dirBrute := flag.Bool("dirbrute", false, "是否启用目录爆破（依赖 app 字典）")
	dictLevel := flag.String("dict", "simple", "目录爆破字典级别: simple|normal|diff")
	dictFile := flag.String("dict-file", "", "自定义目录爆破字典文件路径")
	dictMax := flag.Int("dict-max", 0, "目录爆破最多加载路径条数，0 表示不限制")
	dictConcurrency := flag.Int("dict-concurrency", 50, "目录爆破并发数")
	flag.Parse()

	targets := collectTargets(*target, *ips)
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "target 不能为空，例如: -target example.com 或 -ips 1.1.1.1,example.com")
		os.Exit(1)
	}

	scanner, err := assetprobe.NewScanner(assetprobe.Options{
		Concurrency:    *rate,
		Timeout:        time.Duration(*timeout) * time.Second,
		DetectHomepage: *homepage,
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
		var dirBruteOpts *assetprobe.DirBruteOptions
		if *dirBrute {
			dirBruteOpts = &assetprobe.DirBruteOptions{
				Enable:         true,
				Level:          assetprobe.DirBruteLevel(strings.ToLower(*dictLevel)),
				CustomDictFile: *dictFile,
				MaxPaths:       *dictMax,
				Concurrency:    *dictConcurrency,
			}
		}
		res, err := scanner.Scan(context.Background(), assetprobe.ScanRequest{
			Target:   t,
			PortSpec: *ports,
			Protocol: protocol,
			DirBrute: dirBruteOpts,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan %s failed: %v\n", t, err)
			continue
		}
		output, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(output))
	}
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
